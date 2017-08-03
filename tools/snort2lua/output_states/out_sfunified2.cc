//--------------------------------------------------------------------------
// Copyright (C) 2017-2017 Cisco and/or its affiliates. All rights reserved.
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
// out_sfunified2.cc author Carter Waxman <cwaxman@cisco.com>

#include <sstream>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "rule_states/rule_api.h"
#include "helpers/s2l_util.h"

namespace output
{
    namespace
    {
        //FIXIT-L add when avaiable
        static std::string header = "output sf_unified2: ";

        template<std::string* header_text>
        static ConversionState* unified2_ctor(Converter& c)
        { return new UnsupportedState<header_text>(c); }

    } // namespace

    /**************************
     *******  A P I ***********
     **************************/

    static const ConvertMap unified2_api =
    {
        "sf_unified2",
        unified2_ctor<&header>,
    };

    const ConvertMap* sfunified2_map = &unified2_api;
} // output namespace

