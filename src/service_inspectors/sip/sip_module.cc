//--------------------------------------------------------------------------
// Copyright (C) 2015-2016 Cisco and/or its affiliates. All rights reserved.
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

// sip_module.cc author Bhagyashree Bantwal <bbantwal@cisco.com>

#include "sip_module.h"

#include <assert.h>
#include <sstream>

#include "utils/util.h"

using namespace std;

#define SIP_EVENT_MAX_SESSIONS_STR       "Maximum sessions reached"
#define SIP_EVENT_EMPTY_REQUEST_URI_STR  "Empty request URI"
#define SIP_EVENT_BAD_URI_STR            "URI is too long"
#define SIP_EVENT_EMPTY_CALL_ID_STR      "Empty call-Id"
#define SIP_EVENT_BAD_CALL_ID_STR        "Call-Id is too long"
#define SIP_EVENT_BAD_CSEQ_NUM_STR       "CSeq number is too large or negative"
#define SIP_EVENT_BAD_CSEQ_NAME_STR      "Request name in CSeq is too long"
#define SIP_EVENT_EMPTY_FROM_STR         "Empty From header"
#define SIP_EVENT_BAD_FROM_STR           "From header is too long"
#define SIP_EVENT_EMPTY_TO_STR           "Empty To header"
#define SIP_EVENT_BAD_TO_STR             "To header is too long"
#define SIP_EVENT_EMPTY_VIA_STR          "Empty Via header"
#define SIP_EVENT_BAD_VIA_STR            "Via header is too long"
#define SIP_EVENT_EMPTY_CONTACT_STR      "Empty Contact"
#define SIP_EVENT_BAD_CONTACT_STR        "Contact is too long"
#define SIP_EVENT_BAD_CONTENT_LEN_STR    "Content length is too large or negative"
#define SIP_EVENT_MULTI_MSGS_STR         "Multiple SIP messages in a packet"
#define SIP_EVENT_MISMATCH_CONTENT_LEN_STR        "Content length mismatch"
#define SIP_EVENT_INVALID_CSEQ_NAME_STR           "Request name is invalid"
#define SIP_EVENT_AUTH_INVITE_REPLAY_ATTACK_STR   "Invite replay attack"
#define SIP_EVENT_AUTH_INVITE_DIFF_SESSION_STR    "Illegal session information modification"
#define SIP_EVENT_BAD_STATUS_CODE_STR     "Response status code is not a 3 digit number"
#define SIP_EVENT_EMPTY_CONTENT_TYPE_STR  "Empty Content-type header"
#define SIP_EVENT_INVALID_VERSION_STR     "SIP version is invalid"
#define SIP_EVENT_MISMATCH_METHOD_STR     "Mismatch in METHOD of request and the CSEQ header"
#define SIP_EVENT_UNKOWN_METHOD_STR       "Method is unknown"
#define SIP_EVENT_MAX_DIALOGS_IN_A_SESSION_STR "Maximum dialogs within a session reached"

#define default_methods "invite cancel ack  bye register options"

static const Parameter s_params[] =
{
    { "ignore_call_channel", Parameter::PT_BOOL, nullptr, "false",
      "enables the support for ignoring audio/video data channel" },

    { "max_call_id_len", Parameter::PT_INT, "0:65535", "256",
      "maximum call id field size" },

    { "max_contact_len", Parameter::PT_INT, "0:65535", "256",
      "maximum contact field size" },

    { "max_content_len", Parameter::PT_INT, "0:65535", "1024",
      "maximum content length of the message body" },

    { "max_dialogs", Parameter::PT_INT, "1:4194303", "4",
      "maximum number of dialogs within one stream session" },

    { "max_from_len", Parameter::PT_INT, "0:65535", "256",
      "maximum from field size" },

    { "max_requestName_len", Parameter::PT_INT, "0:65535", "20",
      "maximum request name field size" },

    { "max_sessions", Parameter::PT_INT, "1024:4194303", "10000",
      "maximum number of sessions that can be allocated" },

    { "max_to_len", Parameter::PT_INT, "0:65535", "256",
      "maximum to field size" },

    { "max_uri_len", Parameter::PT_INT, "0:65535", "256",
      "maximum request uri field size" },

    { "max_via_len", Parameter::PT_INT, "0:65535", "1024",
      "maximum via field size" },

    { "methods", Parameter::PT_STRING, nullptr, default_methods,
      "list of methods to check in sip messages" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap sip_rules[] =
{
    { SIP_EVENT_MAX_SESSIONS, SIP_EVENT_MAX_SESSIONS_STR },
    { SIP_EVENT_EMPTY_REQUEST_URI, SIP_EVENT_EMPTY_REQUEST_URI_STR },
    { SIP_EVENT_BAD_URI, SIP_EVENT_BAD_URI_STR },
    { SIP_EVENT_EMPTY_CALL_ID, SIP_EVENT_EMPTY_CALL_ID_STR },
    { SIP_EVENT_BAD_CALL_ID, SIP_EVENT_BAD_CALL_ID_STR },
    { SIP_EVENT_BAD_CSEQ_NUM, SIP_EVENT_BAD_CSEQ_NUM_STR },
    { SIP_EVENT_BAD_CSEQ_NAME, SIP_EVENT_BAD_CSEQ_NAME_STR },
    { SIP_EVENT_EMPTY_FROM, SIP_EVENT_EMPTY_FROM_STR },
    { SIP_EVENT_BAD_FROM, SIP_EVENT_BAD_FROM_STR },
    { SIP_EVENT_EMPTY_TO, SIP_EVENT_EMPTY_TO_STR },
    { SIP_EVENT_BAD_TO, SIP_EVENT_BAD_TO_STR },
    { SIP_EVENT_EMPTY_VIA, SIP_EVENT_EMPTY_VIA_STR },
    { SIP_EVENT_BAD_VIA, SIP_EVENT_BAD_VIA_STR },
    { SIP_EVENT_EMPTY_CONTACT, SIP_EVENT_EMPTY_CONTACT_STR },
    { SIP_EVENT_BAD_CONTACT, SIP_EVENT_BAD_CONTACT_STR },
    { SIP_EVENT_BAD_CONTENT_LEN, SIP_EVENT_BAD_CONTENT_LEN_STR },
    { SIP_EVENT_MULTI_MSGS, SIP_EVENT_MULTI_MSGS_STR },
    { SIP_EVENT_MISMATCH_CONTENT_LEN, SIP_EVENT_MISMATCH_CONTENT_LEN_STR },
    { SIP_EVENT_INVALID_CSEQ_NAME, SIP_EVENT_INVALID_CSEQ_NAME_STR },
    { SIP_EVENT_AUTH_INVITE_REPLAY_ATTACK, SIP_EVENT_AUTH_INVITE_REPLAY_ATTACK_STR },
    { SIP_EVENT_AUTH_INVITE_DIFF_SESSION, SIP_EVENT_AUTH_INVITE_DIFF_SESSION_STR },
    { SIP_EVENT_BAD_STATUS_CODE, SIP_EVENT_BAD_STATUS_CODE_STR },
    { SIP_EVENT_EMPTY_CONTENT_TYPE, SIP_EVENT_EMPTY_CONTENT_TYPE_STR },
    { SIP_EVENT_INVALID_VERSION, SIP_EVENT_INVALID_VERSION_STR },
    { SIP_EVENT_MISMATCH_METHOD, SIP_EVENT_MISMATCH_METHOD_STR },
    { SIP_EVENT_UNKOWN_METHOD, SIP_EVENT_UNKOWN_METHOD_STR },
    { SIP_EVENT_MAX_DIALOGS_IN_A_SESSION, SIP_EVENT_MAX_DIALOGS_IN_A_SESSION_STR },

    { 0, nullptr }
};

THREAD_LOCAL SipStats sip_stats;

static const PegInfo sip_pegs[] =
{
    { "packets", "total packets" },
    { "sessions", "total sessions" },
    { "events", "events generated" },
    { "dialogs", "total dialogs" },
    { "ignored channels", "total channels ignored" },
    { "ignored sessions", "total sessions ignored" },
    { "total requests", "total requests" },
    { "invite", "invite" },
    { "cancel", "cancel" },
    { "ack", "ack" },
    { "bye", "bye" },
    { "register", "register" },
    { "options", "options" },
    { "refer", "refer" },
    { "subscribe", "subscribe" },
    { "update", "update" },
    { "join", "join" },
    { "info", "info" },
    { "message", "message" },
    { "notify", "notify" },
    { "prack", "prack" },
    { "total responses", "total responses" },
    { "1xx", "1xx" },
    { "2xx", "2xx" },
    { "3xx", "3xx" },
    { "4xx", "4xx" },
    { "5xx", "5xx" },
    { "6xx", "6xx" },
    { "7xx", "7xx" },
    { "8xx", "8xx" },
    { "9xx", "9xx" },
    { nullptr, nullptr }
};

//-------------------------------------------------------------------------
// sip module
//-------------------------------------------------------------------------

SipModule::SipModule() : Module(SIP_NAME, SIP_HELP, s_params)
{
    conf = nullptr;
}

SipModule::~SipModule()
{
    if ( conf )
        delete conf;
}

const RuleMap* SipModule::get_rules() const
{ return sip_rules; }

const PegInfo* SipModule::get_pegs() const
{ return sip_pegs; }

PegCount* SipModule::get_counts() const
{ return (PegCount*)&sip_stats; }

ProfileStats* SipModule::get_profile() const
{ return &sipPerfStats; }

bool SipModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("ignore_call_channel") )
        conf->ignoreChannel  = 1;

    else if ( v.is("max_call_id_len") )
        conf->maxCallIdLen = v.get_long();

    else if ( v.is("max_contact_len") )
        conf->maxContactLen = v.get_long();

    else if ( v.is("max_content_len") )
        conf->maxContentLen = v.get_long();

    else if ( v.is("max_dialogs") )
        conf->maxNumDialogsInSession = v.get_long();

    else if ( v.is("max_from_len") )
        conf->maxFromLen = v.get_long();

    else if ( v.is("max_requestName_len") )
        conf->maxRequestNameLen = v.get_long();

    else if ( v.is("max_sessions") )
        conf->maxNumSessions = v.get_long();

    else if ( v.is("max_to_len") )
        conf->maxToLen = v.get_long();

    else if ( v.is("max_uri_len") )
        conf->maxUriLen = v.get_long();

    else if ( v.is("max_via_len") )
        conf->maxViaLen = v.get_long();

    else if ( v.is("methods") )
        sip_methods = v.get_string();

    else
        return false;

    return true;
}

SIP_PROTO_CONF* SipModule::get_data()
{
    SIP_PROTO_CONF* tmp = conf;
    conf = nullptr;
    return tmp;
}

bool SipModule::begin(const char*, int, SnortConfig*)
{
    conf = new SIP_PROTO_CONF;
    conf->ignoreChannel  = 0;
    conf->maxNumSessions = 10000;
    conf->maxNumDialogsInSession = 4;
    conf->maxUriLen = 256;
    conf->maxCallIdLen = 256;
    conf->maxRequestNameLen = 20;
    conf->maxFromLen = 256;
    conf->maxToLen = 256;

    conf->maxViaLen = 1024;
    conf->maxContactLen = 256;
    conf->maxContentLen = 1024;

    conf->methodsConfig = SIP_METHOD_NULL;
    conf->methods = NULL;
    sip_methods = default_methods;
    return true;
}

bool SipModule::end(const char*, int, SnortConfig*)
{
    {
        Value v(sip_methods.c_str());
        std::string tok;
        v.set_first_token();

        while ( v.get_next_token(tok) )
            SIP_ParseMethods(tok.c_str(), &conf->methodsConfig, &conf->methods);
    }
    /*If no methods defined, use the default*/
    if (SIP_METHOD_NULL == conf->methodsConfig)
    {
        SIP_SetDefaultMethods(conf);
    }

    return true;
}

