//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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
// unit_test.h author Russ Combs <rucombs@cisco.com>

#include "unit_test.h"

#include <stdlib.h>
#include <string.h>

#include <vector>
#include <string>

#define CATCH_CONFIG_RUNNER
#include "catch.hpp"

static bool s_catch = false;
static std::vector<std::string> test_tags;

void catch_set_filter(const char* s)
{
    if ( s && strcmp(s, "all") )
        test_tags.push_back( s );

    s_catch = true;
}

bool catch_enabled()
{
    return s_catch;
}

static bool run_catch()
{
  Catch::Session session;

  // write to session.configData() or session.Config() to customize
  //if( s_mode == CK_VERBOSE )
  //    session.configData().showSuccessfulTests = true;

  if( test_tags.size() > 0 )
      session.configData().testsOrTags = test_tags;

  return session.run() == 0;
}

int catch_test()
{
    if ( !run_catch() )
        return -1;

    return 0;
}

