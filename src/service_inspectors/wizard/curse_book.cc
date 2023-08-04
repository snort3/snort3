//--------------------------------------------------------------------------
// Copyright (C) 2023-2023 Cisco and/or its affiliates. All rights reserved.
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
// curse_book.cc author Maya Dagon <mdagon@cisco.com>
// Based on curses.cc

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "curse_book.h"

using namespace std;

// map between service and curse details
vector<CurseDetails> CurseBook::curse_map = 
{
    // name         service        alg                          is_tcp
    { "dce_udp"   , "dcerpc"     , CurseBook::dce_udp_curse   , false },
    { "dce_tcp"   , "dcerpc"     , CurseBook::dce_tcp_curse   , true  },
    { "mms"       , "mms"        , CurseBook::mms_curse       , true  },
    { "s7commplus", "s7commplus" , CurseBook::s7commplus_curse, true  },
    { "dce_smb"   , "netbios-ssn", CurseBook::dce_smb_curse   , true  },
    { "sslv2"     , "ssl"        , CurseBook::ssl_v2_curse    , true  }
};

bool CurseBook::add_curse(const char* key)
{
    for ( const CurseDetails& curse : curse_map )
    {
        if ( curse.name == key )
        {
            if ( curse.is_tcp )
                tcp_curses.emplace_back(&curse);
            else
                non_tcp_curses.emplace_back(&curse);

            return true;
        }
    }

    return false;
}

const vector<const CurseDetails*>& CurseBook::get_curses(bool tcp) const
{
    return tcp ? tcp_curses : non_tcp_curses;
}
