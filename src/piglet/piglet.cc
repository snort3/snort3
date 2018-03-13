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
// piglet.cc author Joel Cornett <jocornet@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "piglet.h"

#include <iostream>
#include <chrono>

#include "main/snort_config.h"

#include "piglet_output.h"
#include "piglet_runner.h"

namespace Piglet
{
int main()
{
    // FIXIT-M allow user selection of output/result functions
    if ( Runner::run_all(verbose_output) )
        return 0;

    return 1;
}

bool piglet_mode()
{ return snort::SnortConfig::get_conf()->run_flags & RUN_FLAG__PIGLET; }
} // namespace Piglet
