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

// cd_ieee8021_module.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "codecs/root/cd_wlan_module.h"


static const Parameter wifi_params[] =
{
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};


static const RuleMap wifi_rules[] =
{
    { DECODE_BAD_80211_ETHLLC, "(" CD_WLAN_NAME ") Bad 802.11 LLC header" },
    { DECODE_BAD_80211_OTHER, "(" CD_WLAN_NAME ") Bad 802.11 Extra LLC Info" },
    { 0, nullptr }
};

//-------------------------------------------------------------------------
// wifi module
//-------------------------------------------------------------------------

WlanCodecModule::WlanCodecModule() : DecodeModule(CD_WLAN_NAME, wifi_params, wifi_rules)
{ }

bool WlanCodecModule::set(const char*, Value&, SnortConfig*)
{
    return true;
}
