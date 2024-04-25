//--------------------------------------------------------------------------
// Copyright (C) 2015-2024 Cisco and/or its affiliates. All rights reserved.
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

// profiler_nodes.cc author Joel Cornett <jocornet@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "profiler_nodes.h"

#include <cassert>
#include <fstream>
#include <mutex>
#include <sys/stat.h>
#include <climits>
#include <unistd.h>

#include "framework/module.h"

#include "main/snort_config.h"
#include "memory_profiler_active_context.h"
#include "profiler_defs.h"
#include "log/messages.h"
#include "time/packet_time.h"
#include "utils/util.h"
#include "utils/util_cstring.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;

static std::string tracker_fname = "mem_profile_stats.csv";
static THREAD_LOCAL FILE* tracker_fd = nullptr;

// -----------------------------------------------------------------------------
// types
// -----------------------------------------------------------------------------

struct GetProfileFunctor
{
    GetProfileFunctor(const std::string& name) : name(name) { }

    virtual ~GetProfileFunctor() = default;
    virtual ProfileStats* operator()() = 0;

    const std::string name;
};

struct GetProfileFromModule : public GetProfileFunctor
{
    GetProfileFromModule(const std::string& pn, Module* m) :
        GetProfileFunctor(pn), m(m) { }

    ProfileStats* operator()() override
    {
        // const auto *ps = m->get_profiler_stats();
        auto *ps = m->get_profile();
        if ( ps )
            return ps;

        unsigned i = 0;
        const char* n, * pn;
        // while ( (ps = m->get_profiler_stats(i++, n, pn)) && name != n );
        while ( (ps = m->get_profile(i++, n, pn)) && name != n );

        return ps;
    }

    Module* m;
};

struct GetProfileFromFunction : public GetProfileFunctor
{
    GetProfileFromFunction(const std::string& pn, get_profile_stats_fn fn) :
        GetProfileFunctor(pn), fn(fn) { }

    ProfileStats* operator()() override
    { return fn(name.c_str()); }

    get_profile_stats_fn fn;
};

// -----------------------------------------------------------------------------
// implementation
// -----------------------------------------------------------------------------

template<typename Getter>
static void setup_node(ProfilerNode& child, ProfilerNode& parent, Getter g)
{
    assert(!child.is_set());
    child.set(g);

    // don't link parent->parent
    if ( child == parent )
        return;

    parent.add_child(&child);
}

void ProfilerNode::set(Module* m)
{ getter = std::make_shared<GetProfileFromModule>(name, m); }

void ProfilerNode::set(get_profile_stats_fn fn)
{ getter = std::make_shared<GetProfileFromFunction>(name, fn); }

void ProfilerNode::accumulate(snort::ProfilerType type)
{
    if ( is_set() )
    {
        const auto* local_stats = (*getter)();

        if ( !local_stats )
            return;

        get_stats();

        if ( type == snort::PROFILER_TYPE_TIME )
            stats += local_stats->time;
        else if ( type == snort::PROFILER_TYPE_MEMORY )
            stats += local_stats->memory;
        else
            stats += *local_stats;
    }
}

void ProfilerNode::reset(ProfilerType type)
{
    if ( is_set() )
    {
        auto* local_stats = (*getter)();

        if ( !local_stats )
            return;

        if ( type == snort::PROFILER_TYPE_TIME )
        {
            stats.reset_time();
            local_stats->reset_time();
        }
        else
        {
            stats.reset();
            local_stats->reset();
        }
    }
}

void ProfilerNodeMap::write_header()
{
    fprintf(tracker_fd, "#timestamp,");

    for ( auto it = nodes.begin(); it != nodes.end(); ++it )
    {
        const char* ins_name = it->second.name.c_str();
        fprintf(tracker_fd, "%s.bytes_allocated,%s.bytes_deallocated,"
            "%s.allocation_count,%s.deallocation_count,", ins_name,
            ins_name, ins_name, ins_name);
    }

    fprintf(tracker_fd, "global.bytes_allocated,global.bytes_deallocated,"
        "global.allocation_count,global.deallocation_count\n");

    fflush(tracker_fd);
}

static void inline write_memtracking_info(const MemoryStats& stats, FILE* fd)
{
    fprintf(fd, "%" PRIu64 ",", (uint64_t)(stats.allocated));
    fprintf(fd, "%" PRIu64 ",", (uint64_t)(stats.deallocated));
    fprintf(fd, "%" PRIu64 ",", (uint64_t)(stats.allocs));
    fprintf(fd, "%" PRIu64 ",", (uint64_t)(stats.deallocs));
}

void ProfilerNode::get_local_memory_stats(FILE* fd)
{
    if (is_set())
    {
        const auto* local_stats = (*getter)();

        if (!local_stats)
            return;

        write_memtracking_info(local_stats->memory.stats, fd);
    }
}

bool ProfilerNodeMap::open(std::string& fname, uint64_t max_file_size, bool append)
{
    if (fname.length())
    {
        struct stat pt;
        mode_t mode =  S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH;
        const char* file_name = fname.c_str();
        bool existed = false;

        tracker_fd = fopen(file_name, "r");
        if (tracker_fd)
        { 
            // Check file before change permission
            if (fstat(fileno(tracker_fd), &pt) == 0)

            {
                existed = true;

                // Only change permission for file owned by root
                if ((0 == pt.st_uid) || (0 == pt.st_gid))
                {
                    if (fchmod(fileno(tracker_fd), mode) != 0)
                    {
                        WarningMessage("Profiler: Unable to change mode of "
                            "stats file '%s' to mode:%u: %s.\n",
                            file_name, mode, get_error(errno));
                    }

                    const SnortConfig* sc = SnortConfig::get_conf();

                    if (fchown(fileno(tracker_fd), sc->get_uid(), sc->get_gid()) != 0)
                    {
                        WarningMessage("Profiler: Unable to change permissions of "
                            "stats file '%s' to user:%d and group:%d: %s.\n",
                            file_name, sc->get_uid(), sc->get_gid(), get_error(errno));
                    }
                }
            }

            fclose(tracker_fd);
            tracker_fd = nullptr;
        }

        // This file needs to be readable by everyone
        mode_t old_umask = umask(022);
        // Append to the existing file if just starting up, otherwise we've
        // rotated so start a new one.
        tracker_fd = fopen(file_name, append ? "a" : "w");
        umask(old_umask);

        if (!tracker_fd)
        {
            ErrorMessage("Profiler: Cannot open stats file '%s'.\n", file_name);
            return false;
        }

        // FIXIT-L refactor rotation so it doesn't require an open file handle
        if (existed and append)
            return rotate(fname, max_file_size);
    }

    return true;
}

// FIXIT-M combine with fileRotate
// FIXIT-M refactor file naming foo to use std::string
static bool rotate_file(const char* old_file, FILE* old_fd,
    uint32_t max_file_size)
{
    time_t ts;
    char rotate_file[PATH_MAX];
    struct stat fstats;
    FILE* rotate_fh;

    if (!old_file)
        return false;

    if (!old_fd)
    {
        ErrorMessage("Profiler: Memtracker stats file \"%s\" "
            "isn't open.\n", old_file);
        return false;
    }

    // Mostly file mode is "a", so can't use rewind() or fseek(). Had to close and reopen.
    fclose(old_fd);
    old_fd = fopen(old_file, "r");

    // Fetching the first timestamp from the file and renaming it by appending the time
    int line = 0;
    int holder;
    
    while((holder=fgetc(old_fd)) != EOF)
    {
        if (holder == '\n')
            line++;
        if (line == 1)
            break;
    }

    // Use the current time if 2nd line is not there
    if (holder == EOF)
        ts = time(nullptr);
    else
    {
        char line_str[15];
        if (!fgets(line_str, 15, old_fd))
            ts = time(nullptr);
        else
        {
            char* p = strtok(line_str, ",");
            ts = atoll(p);
        }
    }

    fclose(old_fd);
    old_fd = nullptr;

    // Create rotate file name based on path, optional prefix and date
    // Need to be mindful that we get 64-bit times on OSX
    SnortSnprintf(rotate_file, PATH_MAX, "%s_" STDu64,  old_file, (uint64_t)ts);

    // If the rotate file doesn't exist, just rename the old one to the new one
    rotate_fh = fopen(rotate_file, "r");
    if (rotate_fh == NULL)
    {
        if (rename(old_file, rotate_file) != 0)
        {
            ErrorMessage("Profiler: Could not rename Memtracker stats "
                "file from \"%s\" to \"%s\": %s.\n",
                old_file, rotate_file, get_error(errno));
        }
    }
    else  // Otherwise, if it does exist, append data from current stats file to it
    {
        char read_buf[4096];
        size_t num_read, num_wrote;
        int rotate_index = 0;
        char rotate_file_with_index[PATH_MAX];

        // This file needs to be readable by everyone
        mode_t old_umask = umask(022);

        fclose(rotate_fh);
        rotate_fh = nullptr;

        do
        {
            do
            {
                rotate_index++;

                // Check to see if there are any files already rotated and indexed
                SnortSnprintf(rotate_file_with_index, PATH_MAX, "%s.%02d",
                    rotate_file, rotate_index);
            }
            while (stat(rotate_file_with_index, &fstats) == 0);

            // Subtract one to append to last existing file
            rotate_index--;

            if (rotate_index == 0)
            {
                rotate_file_with_index[0] = 0;
                rotate_fh = fopen(rotate_file, "a");
            }
            else
            {
                SnortSnprintf(rotate_file_with_index, PATH_MAX, "%s.%02d",
                    rotate_file, rotate_index);
                rotate_fh = fopen(rotate_file_with_index, "a");
            }

            if (!rotate_fh)
            {
                ErrorMessage("Profiler: Could not open Memtracker stats "
                    "archive file \"%s\" for appending: %s.\n",
                    *rotate_file_with_index ? rotate_file_with_index : rotate_file,
                    get_error(errno));
                break;
            }

            old_fd = fopen(old_file, "r");
            if (!old_fd)
            {
                ErrorMessage("Profiler: Could not open Memtracker stats file "
                    "\"%s\" for reading to copy to archive \"%s\": %s.\n",
                    old_file, (*rotate_file_with_index ? rotate_file_with_index :
                    rotate_file), get_error(errno));
                break;
            }

            while (!feof(old_fd))
            {
                // This includes the newline from the file.
                if (!fgets(read_buf, sizeof(read_buf), old_fd))
                {
                    if (feof(old_fd))
                        break;

                    if (ferror(old_fd))
                    {
                        // A read error occurred
                        ErrorMessage("Profiler: Error reading Memtracker stats "
                            "file \"%s\": %s.\n", old_file, get_error(errno));
                        break;
                    }
                }

                num_read = strlen(read_buf);

                if (num_read > 0)
                {
                    int rotate_fd = fileno(rotate_fh);

                    if (fstat(rotate_fd, &fstats) != 0)
                    {
                        ErrorMessage("Profiler: Error getting file "
                            "information for \"%s\": %s.\n",
                            *rotate_file_with_index ? rotate_file_with_index : rotate_file,
                            get_error(errno));
                        break;
                    }

                    if (((uint32_t)fstats.st_size + num_read) > max_file_size)
                    {
                        fclose(rotate_fh);

                        rotate_index++;

                        // Create new file same as before but with an index added to the end
                        SnortSnprintf(rotate_file_with_index, PATH_MAX, "%s.%02d",
                            rotate_file, rotate_index);

                        rotate_fh = fopen(rotate_file_with_index, "a");
                        if (!rotate_fh)
                        {
                            ErrorMessage("Profiler: Could not open Memtracker "
                                "stats archive file \"%s\" for writing: %s.\n",
                                rotate_file_with_index, get_error(errno));
                            break;
                        }
                    }

                    num_wrote = fprintf(rotate_fh, "%s", read_buf);
                    if ((num_wrote != num_read) && ferror(rotate_fh))
                    {
                        // A bad write occurred
                        ErrorMessage("Profiler: Error writing to Memtracker "
                            "stats archive file \"%s\": %s.\n", rotate_file, get_error(errno));
                        break;
                    }

                    fflush(rotate_fh);
                }
            }
        }
        while (false);

        if (rotate_fh)
            fclose(rotate_fh);

        if (old_fd)
            fclose(old_fd);

        umask(old_umask);
    }

    return true;
}

bool ProfilerNodeMap::rotate(std::string& fname, uint64_t max_file_size)
{
    if (tracker_fd)
    {
        if (!rotate_file(fname.c_str(), tracker_fd, max_file_size))
            return false;

        return open(fname, max_file_size, false);
    }

    return false;
}

inline void ProfilerNodeMap::create_new_file(std::string& fname, uint64_t max_file_size)
{
    open(fname, max_file_size, true);
    write_header();
}

void ProfilerNodeMap::auto_rotate(std::string& fname, uint64_t max_file_size)
{
    const char* file_name = fname.c_str();

    if (tracker_fd)
    {
        // If file is deleted, will close the existing fd and reopen the file
        if (access(file_name, F_OK) != 0)
        {
            fclose(tracker_fd);
            tracker_fd = nullptr;
            create_new_file(fname, max_file_size);
        }
        // If file size exceeds max size, will rotate the file and open a new one.
        else if (check_file_size(tracker_fd, max_file_size))
        {
            rotate(fname, max_file_size);
            write_header();
        }
    }
    else
    {
        // If after restart file exists, will append to the existing file.
        FILE* fd = fopen(file_name, "r");
        if (fd)
        {
            if (check_file_size(fd, max_file_size))
            {
                fclose(fd);
                tracker_fd = fopen(file_name, "a");
                return;
            }

            fclose(fd);
        }
        
        create_new_file(fname, max_file_size);
    }

}

void ProfilerNodeMap::print_runtime_memory_stats()
{
    const auto* config = SnortConfig::get_conf()->get_profiler();
    if (!config->memory.show)
        return;

    std::string fname;
    get_instance_file(fname, tracker_fname.c_str());

    auto_rotate(fname, config->memory.dump_file_size);

    timeval cur_time;
    packet_gettimeofday(&cur_time);

    fprintf(tracker_fd, "%" PRIu64 ",", (uint64_t)cur_time.tv_sec);

    for ( auto it = nodes.begin(); it != nodes.end(); ++it )
        it->second.get_local_memory_stats(tracker_fd);

    write_memtracking_info(mp_active_context.get_fallback().stats, tracker_fd);

    fputs("\n", tracker_fd);
    fflush(tracker_fd);
}

void ProfilerNodeMap::register_node(const std::string &n, const char* pn, Module* m)
{ setup_node(get_node(n), get_node(pn ? pn : ROOT_NODE), m); }

void ProfilerNodeMap::accumulate_nodes(ProfilerType type)
{
    static std::mutex stats_mutex;
    std::lock_guard<std::mutex> lock(stats_mutex);

    for ( auto it = nodes.begin(); it != nodes.end(); ++it )
        it->second.accumulate(type);
}

void ProfilerNodeMap::accumulate_flex()
{
    auto it = nodes.find(FLEX_NODE);

    if ( it != nodes.end() )
        it->second.accumulate();
}

void ProfilerNodeMap::clear_flex()
{
    auto it = nodes.find(FLEX_NODE);

    if ( it != nodes.end() )
        it->second.reset();
}

void ProfilerNodeMap::reset_nodes(ProfilerType type)
{
    static std::mutex reset_mutex;
    std::lock_guard<std::mutex> lock(reset_mutex);
    for ( auto it = nodes.begin(); it != nodes.end(); ++it )
        it->second.reset(type);
}

const ProfilerNode& ProfilerNodeMap::get_root()
{ return get_node(ROOT_NODE); }

ProfilerNode& ProfilerNodeMap::get_node(const std::string& key)
{
    auto node = nodes.emplace(key, key);
    return node.first->second;
}

#ifdef UNIT_TEST

static ProfilerNode find_node(const ProfilerNodeMap& tree, const std::string& name)
{
    for ( const auto& it : tree )
    {
        if ( it.first == name )
            return it.second;
    }

    return ProfilerNode("");
}

namespace
{

class SpyModule : public Module
{
public:
    SpyModule(const char* name, ProfileStats* stats, bool multi) :
        Module(name, nullptr), stats(stats), multi(multi) { }

    ProfileStats* get_stats() { return stats; }
    void set_stats(ProfileStats* ps) { stats = ps; }
    void set_multi(bool b) { multi = b; }

    ProfileStats* get_profile() const override
    { return multi ? nullptr : stats; }

    ProfileStats* get_profile(
        unsigned i, const char*& name, const char*&) const override
    {
        if ( !multi )
            return nullptr;

        if ( i == 0 )
        {
            name = "dummy";
            return &dummy_stats;
        }

        else if ( i == 1 )
        {
            name = get_name();
            return stats;
        }

        return nullptr;
    }

private:
    ProfileStats* stats;
    bool multi;

    mutable ProfileStats dummy_stats;
};

} // anonymous namespace

TEST_CASE( "get profile functor for module", "[profiler]" )
{
    ProfileStats the_stats;
    SpyModule m("foo", &the_stats, false);
    GetProfileFromModule functor("foo", &m);

    SECTION( "one" )
    {
        CHECK( functor() == &the_stats );
    }

    SECTION( "many" )
    {
        m.set_multi(true);
        CHECK( functor() == &the_stats );
    }
}

TEST_CASE( "profiler node", "[profiler]" )
{
    ProfileStats the_stats;
    SpyModule m("foo", &the_stats, false);

    ProfilerNode node("foo");
    node.set(&m);

    SECTION( "get_stats" )
    {
        auto& result = node.get_stats();
        CHECK( result == ProfileStats() );
    }

    SECTION( "set" )
    {
        the_stats.time = { 5_ticks, 7 };

        SECTION( "module" )
        {
            node.accumulate();
            CHECK( node.get_stats() == the_stats );
        }
    }

    SECTION( "accumulate" )
    {
        the_stats.time = { 1_ticks, 1 };

        node.accumulate();
        node.accumulate();

        auto& result = node.get_stats();

        CHECK( (result.time.elapsed == 2_ticks) );
        CHECK( (result.time.checks == 2) );
    }

    SECTION( "reset" )
    {
        the_stats.time = { 1_ticks, 1 };

        node.accumulate();

        auto& r1 = node.get_stats();
        CHECK( r1 != ProfileStats() );

        node.reset();
        auto& r2 = node.get_stats();
        CHECK( r2 == ProfileStats() );
    }
}

TEST_CASE( "profiler node map", "[profiler]" )
{
    ProfilerNodeMap tree;

    SECTION( "register" )
    {
        ProfileStats stats;
        SpyModule m("foo", &stats, false);

        SECTION( "register module" )
        {
            tree.register_node("foo", nullptr, &m);
            CHECK( !find_node(tree, "foo").name.empty() );
        }

        SECTION( "register child -> parent" )
        {
            tree.register_node("foo", "bar", &m);
            auto node = find_node(tree, "bar");
            CHECK( !node.get_children().empty() );
            CHECK( node.get_children().front()->name == "foo" );
        }

        SECTION( "register child -> null" )
        {
            tree.register_node("foo", nullptr, &m);
            auto root = tree.get_root();
            CHECK( !root.get_children().empty() );
            CHECK( root.get_children().front()->name == "foo" );
        }

        SECTION( "register parent -> parent" )
        {
            tree.register_node("foo", "foo", &m);
            auto node = find_node(tree, "foo");
            CHECK( node.get_children().empty() );
        }
    }

    SECTION( "get root" )
    {
        CHECK( tree.get_root().name == ROOT_NODE );
    }
}

#endif
