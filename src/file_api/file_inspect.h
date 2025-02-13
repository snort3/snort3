//--------------------------------------------------------------------------
// Copyright (C) 2015-2025 Cisco and/or its affiliates. All rights reserved.
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

// author Hui Cao <huica@cisco.com>

#ifndef FILE_INSPECT_H
#define FILE_INSPECT_H

// file processing configuration
//
#include "framework/inspector.h"

class FileInspect : public snort::Inspector
{
public:
    FileInspect(class FileIdModule*);
    ~FileInspect() override;
    void eval(snort::Packet*) override { }
    bool configure(snort::SnortConfig*) override;
    void show(const snort::SnortConfig*) const override;
    class FileConfig* config;
};

#endif

