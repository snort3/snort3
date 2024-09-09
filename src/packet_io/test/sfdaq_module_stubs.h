//--------------------------------------------------------------------------
// Copyright (C) 2024 Cisco and/or its affiliates. All rights reserved.
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
// sfdaq_module_stubs.h author Arunkumar Kayambu <akayambu@cisco.com>

#include "main/snort.h"
#include "packet_io/sfdaq_instance.h"
#include "packet_io/sfdaq_config.h"
#include "../trough.h"

#ifndef SFDAQ_MODULE_STUBS_H
#define SFDAQ_MODULE_STUBS_H

namespace snort
{
Module::Module(char const*, char const*, snort::Parameter const*, bool)
{
    help = nullptr;
    name = nullptr;
    params = nullptr;
    list = false;
}
PegCount Module::get_global_count(const char*) const { return 0; }
void Module::sum_stats(bool) { }
void Module::init_stats(bool) { }
void Module::main_accumulate_stats() { }
void Module::show_interval_stats(std::vector<unsigned>&, FILE*) { }
void Module::show_stats() { }
void Module::reset_stats() { }
void ParseError(char const*, ...)  {}
SFDAQInstance::SFDAQInstance(char const*, unsigned int, SFDAQConfig const*)
{
    batch_size = 0;
    instance_id = 1;
    daq_msgs = nullptr;
}
SFDAQInstance::~SFDAQInstance() { }
}

SFDAQConfig::SFDAQConfig()
{
   batch_size = 0;
   mru_size = 0;
   timeout = 0;
}
SFDAQConfig::~SFDAQConfig() = default;
void SFDAQModuleConfig::set_variable(char const*){}
void SFDAQConfig::add_module_dir(char const*){}
void SFDAQConfig::add_input(char const*){}
void SFDAQConfig::set_mru_size(int){}
void SFDAQConfig::set_batch_size(unsigned int){}
void SFDAQConfig::overlay(SFDAQConfig const*){}
std::atomic<unsigned> Trough::file_count{0};
#endif
