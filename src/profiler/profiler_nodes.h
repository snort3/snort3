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

// profiler_nodes.h author Joel Cornett <jocornet@cisco.com>

#ifndef PROFILER_NODES_H
#define PROFILER_NODES_H

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "profiler_defs.h"

namespace snort
{
class Module;
}
struct GetProfileFunctor;

class ProfilerNode
{
public:
    ProfilerNode(const std::string& key) :
        name { key } { }

    void set(snort::Module* m);
    void set(snort::get_profile_stats_fn fn);

    bool is_set() const
    { return bool(getter); }

    // thread local call
    void accumulate(snort::ProfilerType = snort::PROFILER_TYPE_BOTH);

    const snort::ProfileStats& get_stats() const
    { return stats; }

    void set_stats(const snort::ProfileStats& ps)
    { stats = ps; }

    void reset(snort::ProfilerType = snort::PROFILER_TYPE_BOTH);

    void add_child(ProfilerNode* node)
    { children.emplace_back(node); }

    const std::vector<ProfilerNode*> get_children() const
    { return children; }

    const std::string name;

    void get_local_memory_stats(FILE*);

private:
    std::vector<ProfilerNode*> children;
    std::shared_ptr<GetProfileFunctor> getter;
    snort::ProfileStats stats;
};

inline bool operator==(const ProfilerNode& lhs, const ProfilerNode& rhs)
{ return lhs.name == rhs.name; }

inline bool operator!=(const ProfilerNode& lhs, const ProfilerNode& rhs)
{ return lhs.name == rhs.name; }

class ProfilerNodeMap
{
public:
    using map_type = std::unordered_map<std::string, ProfilerNode>;

    map_type::const_iterator begin() const
    { return nodes.begin(); }

    map_type::const_iterator end() const
    { return nodes.end(); }

    void register_node(const std::string&, const char*, snort::Module*);

    void accumulate_nodes(snort::ProfilerType = snort::PROFILER_TYPE_BOTH);
    void accumulate_flex();
    void clear_flex();
    void reset_nodes(snort::ProfilerType = snort::PROFILER_TYPE_BOTH);

    void print_runtime_memory_stats();

    inline void create_new_file(std::string&, uint64_t);
    void auto_rotate(std::string&, uint64_t);
    bool rotate(std::string&, uint64_t);
    bool open(std::string&, uint64_t, bool);
    void write_header();

    const ProfilerNode& get_root();

private:
    ProfilerNode& get_node(const std::string&);

    map_type nodes;
};

#endif
