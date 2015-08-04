//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
// cmd_line.cc author Russ Combs <rucombs@cisco.com>

#include "cmd_line.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string>
using namespace std;

#include "main/help.h"
#include "main/snort_module.h"
#include "main/snort_config.h"
#include "framework/module.h"
#include "framework/parameter.h"
#include "packet_io/trough.h"
#include "parser/arg_list.h"
#include "parser/parser.h"
#include "utils/util.h"

//-------------------------------------------------------------------------

static void check_flags(SnortConfig* sc)
{
    if ((sc->run_flags & RUN_FLAG__TEST) &&
        (sc->run_flags & RUN_FLAG__DAEMON))
    {
        FatalError("Cannot use test mode and daemon mode together.\n"
            "To verify configuration, run first in test "
            "mode and then restart in daemon mode.\n");
    }

    if ((sc->run_flags & RUN_FLAG__INLINE) &&
        (sc->run_flags & RUN_FLAG__INLINE_TEST))
    {
        FatalError("Cannot use inline adapter mode and inline test "
            "mode together. \n");
    }

    if (Trough_GetLoopCount() && !(sc->run_flags & RUN_FLAG__READ))
    {
        FatalError("--pcap-loop can only be used in combination with pcaps "
            "on the command line.\n");
    }

    if ((sc->run_flags & RUN_FLAG__PCAP_RELOAD) &&
        !(sc->run_flags & RUN_FLAG__READ))
    {
        FatalError("--pcap-reload can only be used in combination with pcaps "
            "on the command line.\n");
    }
}

//-------------------------------------------------------------------------

static bool set_arg(
    Module* m, const Parameter* p,
    const char* key, const char* val, SnortConfig* sc)
{
    Value v(key);
    bool ok = true;

    switch ( p->type )
    {
    case Parameter::PT_IMPLIED:
        if ( *val )
            ok = false;
        else
            v.set(true);
        break;

    case Parameter::PT_INT:
    case Parameter::PT_PORT:
    {
        char* end = nullptr;
        long n = strtol(val, &end, 0);

        if ( !*end )
            v.set(n);
        else
            ok = false;
        break;
    }
    case Parameter::PT_REAL:
    {
        char* end = nullptr;
        double d = strtod(val, &end);

        if ( !*end )
            v.set(d);
        else
            ok = false;
        break;
    }
    default:
        v.set(val);
    }

    if ( ok && p->validate(v) )
    {
        v.set(p);

        if ( m->set(p->name, v, sc) )
            return true;
    }
    return false;
}

//-------------------------------------------------------------------------

static bool is_special(const char* key)
{
    return ( strlen(key) == 1 && strchr("MEDq", *key) );
}

static void set(
    const char* key, const char* val, SnortConfig* sc, bool all)
{
    if ( !all == !is_special(key) )
        return;

    string k = "-";
    if (strlen(key) > 1)
        k += "-";
    k += key;
    key = k.c_str();

    Module* m = get_snort_module();
    const Parameter* p = m->get_parameters();
    p = Parameter::find(p, key);

    if ( !p )
        ParseError("unknown option %s %s", key, val);

    else if ( !set_arg(m, p, k.c_str(), val, sc) )
    {
        ParseError("can't set %s %s", key, val);
        ParseError("usage: %s %s", key, p->help);
    }
}

//-------------------------------------------------------------------------

SnortConfig* parse_cmd_line(int argc, char* argv[])
{
    SnortConfig* sc = new SnortConfig;
    Module* sm = get_snort_module();

    ArgList al(argc, argv);
    const char* key, * val;
    unsigned c = 0;

    sm->begin(nullptr, 0, sc);

    // get special options first
    while ( al.get_arg(key, val) )
    {
        ::set(key, val, sc, false);
        c++;
    }

    // now get the rest
    al.reset();

    while ( al.get_arg(key, val) )
    {
        ::set(key, val, sc, true);
        c++;
    }

    if ( !c )
        help_usage(sc, argv[0]);

    else if ( sm->end(nullptr, 0, sc) )
        check_flags(sc);

    if ( int k = get_parse_errors() )
        FatalError("see prior %d errors\n", k);

    return sc;
}

//-------------------------------------------------------------------------

void set_daemon_args(int argc, char* argv[])
{
    for ( int i = 1; i < argc; ++i )
    {
        if ( !strcmp(argv[i], "-D") )
        {
            argv[i][1] = 'E';
            break;
        }
    }
}

