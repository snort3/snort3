/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

// cd_esp_module.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "codecs/ip/cd_esp_module.h"
#include "main/snort_config.h"


static const Parameter esp_params[] =
{
    { "decode_esp", Parameter::PT_BOOL, nullptr, "false",
      "enable for inspection of esp traffic that has authentication but not encryption" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};


// rules which will loaded into snort. 
// You can now reference these rules by calling a codec_event
// in your main codec's functions
static const RuleMap esp_rules[] =
{
    { DECODE_ESP_HEADER_TRUNC, "(" CD_ESP_NAME ") truncated Encapsulated Security Payload (ESP) header" },
    { 0, nullptr }
};

//-------------------------------------------------------------------------
// rpc module
//-------------------------------------------------------------------------

EspModule::EspModule() : DecodeModule(CD_ESP_NAME, esp_params, esp_rules)
{ }

bool EspModule::set(const char*, Value& v, SnortConfig* sc)
{
    if ( v.is("decode_esp") )
        sc->enable_esp = v.get_bool();
    else
        return false;

    return true;
}


