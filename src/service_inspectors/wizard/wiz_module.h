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

// wiz_module.cc author Russ Combs <rucombs@cisco.com>

#ifndef WIZ_MODULE_H
#define WIZ_MODULE_H

#include <string>
#include <vector>
#include "framework/module.h"

class MagicBook;

class WizardModule : public Module
{
public:
    WizardModule();
    ~WizardModule();

    bool set(const char*, Value&, SnortConfig*);
    bool begin(const char*, int, SnortConfig*);
    bool end(const char*, int, SnortConfig*);

    MagicBook* get_book(bool c2s, bool hex);

private:
    void add_spells(MagicBook*, std::string&);

private:
    bool hex;
    bool c2s;

    std::string service;
    std::vector<std::string> spells;

    MagicBook* c2s_hexes;
    MagicBook* s2c_hexes;

    MagicBook* c2s_spells;
    MagicBook* s2c_spells;
};

#endif

