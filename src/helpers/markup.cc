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
// markup.cc author Russ Combs <rucombs@cisco.com>

#include "markup.h"
using namespace std;

bool Markup::enabled = false;

void Markup::enable(bool e)
{ enabled = e; }

const char* Markup::head()
{ return enabled ? "=== " : ""; }

const char* Markup::item()
{ return enabled ? "* " : ""; }

const char* Markup::emphasis_on()
{ return enabled ? "*" : ""; }

const char* Markup::emphasis_off()
{ return enabled ? "*" : ""; }

const string& Markup::emphasis(const string& s)
{
    static string m;
    m.clear();
    m += emphasis_on();
    m += s;
    m += emphasis_off();
    return m;
}

