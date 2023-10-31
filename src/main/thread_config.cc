//--------------------------------------------------------------------------
// Copyright (C) 2016-2023 Cisco and/or its affiliates. All rights reserved.
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
// thread_config.cc author Michael Altizer <mialtize@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "thread_config.h"

#include <atomic>

#include "analyzer_command.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "time/periodic.h"
#include "utils/util.h"

#ifdef HAVE_NUMA
#include "utils/util_numa.h"
#endif

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;
using namespace std;

static hwloc_topology_t topology = nullptr;
static hwloc_cpuset_t process_cpuset = nullptr;
static const struct hwloc_topology_support* topology_support = nullptr;
static unsigned instance_max = 1;
static std::mutex instance_mutex;
static std::map<int, int> instance_id_to_tid;

#ifdef HAVE_NUMA

std::shared_ptr<NumaWrapper> numa;
std::shared_ptr<HwlocWrapper> hwloc;

#endif

struct CpuSet
{
    CpuSet(hwloc_cpuset_t set) : cpuset(set) { }
    ~CpuSet()
    {
        if (cpuset)
            hwloc_bitmap_free(cpuset);
    }

    hwloc_cpuset_t cpuset;
};

bool ThreadConfig::init()
{
#ifdef HAVE_NUMA

    numa = std::make_shared<NumaWrapper>();
    hwloc = std::make_shared<HwlocWrapper>();

#endif

    if (hwloc_topology_init(&topology))
        return false;
    if (hwloc_topology_load(topology))
    {
        hwloc_topology_destroy(topology);
        return false;
    }
    topology_support = hwloc_topology_get_support(topology);
    if (topology_support->cpubind->get_thisproc_cpubind)
    {
        process_cpuset = hwloc_bitmap_alloc();
        hwloc_get_cpubind(topology, process_cpuset, HWLOC_CPUBIND_PROCESS);
    }
    else
        process_cpuset = hwloc_bitmap_dup(hwloc_topology_get_allowed_cpuset(topology));
    return true;
}

void ThreadConfig::set_instance_max(unsigned max)
{
    if (max)
        instance_max = max;
    else
    {
        /* A max of 0 indicates automatic allocation.  Set the instance max to the total number of
            CPUs in the our process's running cpuset. */
        instance_max = hwloc_bitmap_weight(process_cpuset);
    }
}

unsigned ThreadConfig::get_instance_max()
{
    return instance_max;
}

CpuSet* ThreadConfig::validate_cpuset_string(const char* cpuset_str)
{
    hwloc_bitmap_t cpuset = hwloc_bitmap_alloc();
    if (hwloc_bitmap_list_sscanf(cpuset, cpuset_str) ||
            !hwloc_bitmap_isincluded(cpuset, process_cpuset))
    {
        hwloc_bitmap_free(cpuset);
        return nullptr;
    }
    return new CpuSet(cpuset);
}

void ThreadConfig::destroy_cpuset(CpuSet *cpuset)
{
    delete cpuset;
}

void ThreadConfig::term()
{
    if (topology)
    {
        hwloc_topology_destroy(topology);
        topology = nullptr;
    }
    if (process_cpuset)
    {
        hwloc_bitmap_free(process_cpuset);
        process_cpuset = nullptr;
    }
    topology_support = nullptr;

#ifdef HAVE_NUMA

    numa.reset();
    hwloc.reset();

#endif
}

ThreadConfig::~ThreadConfig()
{
    for (const auto& iter : thread_affinity)
        delete iter.second;

    for (const auto& iter : named_thread_affinity)
        delete iter.second;
}

void ThreadConfig::set_thread_affinity(SThreadType type, unsigned id, CpuSet* cpuset)
{
    if (topology_support->cpubind->set_thisthread_cpubind)
    {
        TypeIdPair key { type, id };

        auto iter = thread_affinity.find(key);
        if (iter != thread_affinity.end())
            delete iter->second;
        thread_affinity[key] = cpuset;
    }
    else
    {
        delete cpuset;
        ParseWarning(WARN_CONF, "This platform does not support setting thread affinity.\n");
    }
}

void ThreadConfig::set_named_thread_affinity(const string& name, CpuSet* cpuset)
{
    if (topology_support->cpubind->set_thisthread_cpubind)
    {
        auto iter = named_thread_affinity.find(name);
        if (iter != named_thread_affinity.end())
            delete iter->second;
        named_thread_affinity[name] = cpuset;
    }
    else
        ParseWarning(WARN_CONF, "This platform does not support setting thread affinity.\n");
}

void ThreadConfig::set_instance_tid(int id)
{
    std::lock_guard<std::mutex> lock(instance_mutex);
    instance_id_to_tid.emplace(id, (int)gettid());
}

int ThreadConfig::get_instance_tid(int id)
{
    std::lock_guard<std::mutex> lock(instance_mutex);
    int ret = -1;
    auto iter = instance_id_to_tid.find(id);
    if ( iter != instance_id_to_tid.end() )
        ret = iter->second;
    return ret;
}

static inline string stringify_thread(const SThreadType& type, const unsigned& id)
{
    string info;
    if ( type == STHREAD_TYPE_MAIN )
        info = "main thread ";
    else if ( type == STHREAD_TYPE_PACKET )
        info = "packet thread ";
    else
        info = "other thread ";
    info += to_string(id) + " (TID " + to_string((int)gettid()) + ")";
    return info;
}

void ThreadConfig::apply_thread_policy(SThreadType type, unsigned id)
{
    implement_thread_affinity( type, id );

#ifdef HAVE_NUMA

    implement_thread_mempolicy( type, id );

#endif
}

#ifdef HAVE_NUMA

int ThreadConfig::get_numa_node(hwloc_topology_t topology, hwloc_cpuset_t cpuset)
{
    int depth = hwloc->get_type_depth(topology, HWLOC_OBJ_NODE);
    if (depth == HWLOC_TYPE_DEPTH_UNKNOWN)
        return -1;

    for (unsigned i = 0; i < hwloc->get_nbobjs_by_depth(topology, depth); ++i)
    {
        hwloc_obj_t node = hwloc->get_obj_by_depth(topology, depth, i);
        if (node and hwloc->bitmap_intersects(cpuset, node->cpuset))
            return node->os_index;
    }
    return -1;
}

bool ThreadConfig::set_preferred_mempolicy(int node)
{
    if (node < 0)
        return false;

    unsigned long nodemask = 1UL << (unsigned long)node;
    int result = numa->set_mem_policy(MPOL_PREFERRED, &nodemask, sizeof(nodemask)*8);
    if (result != 0)
        return false;

    if(numa->preferred() != node)
        return false;

    return true;
}

bool ThreadConfig::implement_thread_mempolicy(SThreadType type, unsigned id)
{
    if (!topology_support->cpubind->set_thisthread_cpubind or
                numa->available() < 0 or numa->max_node() <= 0)
    {
        return false;
    }

    TypeIdPair key { type, id };
    auto iter = thread_affinity.find(key);
    if (iter != thread_affinity.end())
    {
        int node_index = get_numa_node(topology, iter->second->cpuset);
        if(set_preferred_mempolicy(node_index))
            LogMessage( "Preferred memory policy set for %s to node %d\n",stringify_thread(type, id).c_str(), node_index);
        else
            return false;
        }
    else
    {
        return false;
    }

    return true;
}

#endif

void ThreadConfig::implement_thread_affinity(SThreadType type, unsigned id)
{
    if (!topology_support->cpubind->set_thisthread_cpubind)
        return;

    TypeIdPair key { type, id };
    hwloc_cpuset_t current_cpuset, desired_cpuset;
    char* s;

    auto iter = thread_affinity.find(key);
    if (iter != thread_affinity.end())
        desired_cpuset = iter->second->cpuset;
    else
        desired_cpuset = process_cpuset;

    // A data race in this library function ensues from the usage of a static variable
    // to dump chars when calculating string length. This does not affect functionality.
    hwloc_bitmap_list_asprintf(&s, desired_cpuset);

    current_cpuset = hwloc_bitmap_alloc();
    hwloc_get_cpubind(topology, current_cpuset, HWLOC_CPUBIND_THREAD);
    if (!hwloc_bitmap_isequal(current_cpuset, desired_cpuset))
        LogMessage("Binding %s to CPU %s.\n", stringify_thread(type, id).c_str(), s);
    hwloc_bitmap_free(current_cpuset);

    if (hwloc_set_cpubind(topology, desired_cpuset, HWLOC_CPUBIND_THREAD))
    {
        FatalError("Failed to pin %s to CPU %s: %s (%d)\n",
            stringify_thread(type, id).c_str(), s, get_error(errno), errno);
    }

    free(s);
}

void ThreadConfig::implement_named_thread_affinity(const string& name)
{
    if (!topology_support->cpubind->set_thisthread_cpubind)
        return;

    auto iter = named_thread_affinity.find(name);
    if (iter != named_thread_affinity.end())
    {
        char* s;

        auto desired_cpuset = iter->second->cpuset;
        hwloc_bitmap_list_asprintf(&s, desired_cpuset);

        auto current_cpuset = hwloc_bitmap_alloc();
        hwloc_get_cpubind(topology, current_cpuset, HWLOC_CPUBIND_THREAD);
        if (!hwloc_bitmap_isequal(current_cpuset, desired_cpuset))
            LogMessage("Binding thread %s to %s.\n", name.c_str(), s);
        hwloc_bitmap_free(current_cpuset);

        if (hwloc_set_cpubind(topology, desired_cpuset, HWLOC_CPUBIND_THREAD))
        {
            FatalError("Failed to pin thread %s to %s: %s (%d)\n",
                name.c_str(), s, get_error(errno), errno);
        }

        free(s);
    }
    else
        implement_thread_affinity(get_thread_type(), DEFAULT_THREAD_ID);
}

// watchdog stuff
struct Watchdog
{
    Watchdog(uint16_t tm) : seconds_count(tm)
    {
        resp = new std::atomic_bool[ThreadConfig::get_instance_max()];
    }
    ~Watchdog() { delete[] resp; }
    void kick();
    bool waiting = false;
    std::atomic_bool* resp;
    uint16_t seconds_count;
};

class WatchdogKick : public AnalyzerCommand
{
public:
    WatchdogKick(Watchdog* d) : dog(d) { }
    bool execute(Analyzer&, void**) override
    {
        dog->resp[get_instance_id()] = true;
        return true;
    }
    const char* stringify() override { return "WATCHDOG_KICK"; }

    ~WatchdogKick() override { }
private:
    Watchdog* dog;
};

void Watchdog::kick()
{
    unsigned max = ThreadConfig::get_instance_max();
    if ( waiting )
    {
        uint16_t thread_count = 0;
        for ( unsigned i = 0; i < max; ++i )
        {
            if ( !resp[i] )
            {
                ++thread_count;
                if (thread_count == 1)
                {
                    WarningMessage("Packet processing threads are unresponsive\n");
                    WarningMessage("Unresponsive thread ID: ");
                }
                const int tid = SnortConfig::get_conf()->thread_config->get_instance_tid(i);
                if ( tid != -1 )
                    WarningMessage("%d (TID: %d)", i, tid);
                else
                    WarningMessage("%d ", i);
            }
        }

        if ( thread_count )
            WarningMessage("\n");

        if ( thread_count >= SnortConfig::get_conf()->watchdog_min_thread_count )
        {
            WarningMessage("Aborting Snort\n");
            abort();
        }
    }

    for ( unsigned i = 0; i < max; ++i )
        resp[i] = false;

    main_broadcast_command(new WatchdogKick(this), nullptr);
    waiting = true;
}

static Watchdog& get_watchdog()
{
    static Watchdog s_dog(SnortConfig::get_conf()->watchdog_timer);
    return s_dog;
}

static void s_watchdog_handler(void*)
{
    Watchdog& dog = get_watchdog();
    if ( SnortConfig::get_conf()->watchdog_timer > 0 )
    {
        if ( dog.seconds_count > 0 )
            dog.seconds_count--;
        else
        {
            dog.kick();
            dog.seconds_count = SnortConfig::get_conf()->watchdog_timer;
        }
    }
}

void ThreadConfig::start_watchdog()
{
    Periodic::register_handler(s_watchdog_handler, nullptr, 0, 1000);
}

void ThreadConfig::preemptive_kick()
{
    if (SnortConfig::get_conf()->watchdog_timer)
    {
        Watchdog& dog = get_watchdog();
        dog.resp[get_instance_id()] = true;
    }
}


// -----------------------------------------------------------------------------
// unit tests
// -----------------------------------------------------------------------------

#ifdef UNIT_TEST

TEST_CASE("Parse cpuset string negative test", "[ThreadConfig]")
{
    CpuSet* cpuset = ThreadConfig::validate_cpuset_string("totally a bad cpuset string");
    CHECK(cpuset == nullptr);
}

TEST_CASE("Parse cpuset string positive test", "[ThreadConfig]")
{
    char* s;
    hwloc_bitmap_list_asprintf(&s, process_cpuset);
    CpuSet* cpuset = ThreadConfig::validate_cpuset_string(s);
    free(s);
    CHECK(cpuset != nullptr);
    ThreadConfig::destroy_cpuset(cpuset);
}

TEST_CASE("Set and check max packet threads", "[ThreadConfig]")
{
    CHECK(ThreadConfig::get_instance_max() == 1);
    unsigned new_max = hwloc_bitmap_weight(process_cpuset) * 2;
    ThreadConfig::set_instance_max(new_max);
    CHECK(ThreadConfig::get_instance_max() == new_max);
    ThreadConfig::set_instance_max(0);
    CHECK(ThreadConfig::get_instance_max() == (unsigned)hwloc_bitmap_weight(process_cpuset));
}

TEST_CASE("Set and implement thread affinity", "[ThreadConfig]")
{
    if (topology_support->cpubind->set_thisthread_cpubind)
    {
        CpuSet* cpuset = new CpuSet(hwloc_bitmap_dup(process_cpuset));
        CpuSet* cpuset2 = new CpuSet(hwloc_bitmap_dup(process_cpuset));
        ThreadConfig tc;

        hwloc_bitmap_singlify(cpuset->cpuset);
        tc.set_thread_affinity(STHREAD_TYPE_PACKET, 0, cpuset2);
        tc.set_thread_affinity(STHREAD_TYPE_PACKET, 0, cpuset);
        tc.implement_thread_affinity(STHREAD_TYPE_PACKET, 0);

        hwloc_cpuset_t thread_cpuset = hwloc_bitmap_alloc();
        hwloc_get_cpubind(topology, thread_cpuset, HWLOC_CPUBIND_THREAD);
        CHECK(hwloc_bitmap_isequal(thread_cpuset, cpuset->cpuset));

        tc.implement_thread_affinity(STHREAD_TYPE_MAIN, 0);
        hwloc_get_cpubind(topology, thread_cpuset, HWLOC_CPUBIND_THREAD);
        CHECK(hwloc_bitmap_isequal(thread_cpuset, process_cpuset));

        hwloc_bitmap_free(thread_cpuset);
    }
}

TEST_CASE("Named thread affinity configured", "[ThreadConfig]")
{
    if (topology_support->cpubind->set_thisthread_cpubind)
    {
        CpuSet* cpuset = new CpuSet(hwloc_bitmap_dup(process_cpuset));
        ThreadConfig tc;

        hwloc_cpuset_t thread_cpuset = hwloc_bitmap_alloc();

        // Configure named thread.
        hwloc_bitmap_singlify(cpuset->cpuset);
        tc.set_named_thread_affinity("found", cpuset);

        // The one in the named map, should have the specified cpuset.
        tc.implement_named_thread_affinity("found");
        hwloc_get_cpubind(topology, thread_cpuset, HWLOC_CPUBIND_THREAD);
        CHECK(hwloc_bitmap_isequal(thread_cpuset, cpuset->cpuset));

        // The one not in the named map, should have the process cpuset
        // if no type has been configured for it.
        tc.implement_named_thread_affinity("not found, no type configured");
        hwloc_get_cpubind(topology, thread_cpuset, HWLOC_CPUBIND_THREAD);
        CHECK(hwloc_bitmap_isequal(thread_cpuset, process_cpuset));

        hwloc_bitmap_free(thread_cpuset);
    }
}

TEST_CASE("Named thread affinity with type configured", "[ThreadConfig]")
{
    if (topology_support->cpubind->set_thisthread_cpubind)
    {
        CpuSet* type_cpuset = new CpuSet(hwloc_bitmap_dup(process_cpuset));
        ThreadConfig tc;

        hwloc_cpuset_t thread_cpuset = hwloc_bitmap_alloc();

        // Configure type affinity, but not the named thread affinity.
        hwloc_bitmap_singlify(type_cpuset->cpuset);
        tc.set_thread_affinity(STHREAD_TYPE_MAIN, ThreadConfig::DEFAULT_THREAD_ID, type_cpuset);

        // The named thread should inherit the type affinity.
        tc.implement_named_thread_affinity("not found, type other");
        hwloc_get_cpubind(topology, thread_cpuset, HWLOC_CPUBIND_THREAD);
        CHECK(hwloc_bitmap_isequal(thread_cpuset, type_cpuset->cpuset));

        hwloc_bitmap_free(thread_cpuset);
    }
}

#ifdef HAVE_NUMA

class NumaWrapperMock : public NumaWrapper
{
public:
    int numa_avail = 1;
    int max_n = 1;
    int pref = 0;
    int mem_policy = 0;

    int available() override { return numa_avail; }
    int max_node() override { return max_n; }
    int preferred() override { return pref; }
    int set_mem_policy(int , const unsigned long *,
                              unsigned long ) override
    { return mem_policy; }
};

class HwlocWrapperMock : public HwlocWrapper
{
public:
    int nbobjs_by_depth = 1;
    int type_depth = 2;
    int intersects = 1;
    struct hwloc_obj node;

    unsigned get_nbobjs_by_depth(hwloc_topology_t , int ) override
    { return nbobjs_by_depth; }
    hwloc_obj_t get_obj_by_depth(hwloc_topology_t, int, unsigned ) override
    { return &node; }
    int get_type_depth(hwloc_topology_t, hwloc_obj_type_t ) override
    { return type_depth; }
    int bitmap_intersects(hwloc_const_cpuset_t, hwloc_const_cpuset_t ) override
    { return intersects; }
};

TEST_CASE("set node for thread", "[ThreadConfig]")
{
    CpuSet* cpuset = new CpuSet(hwloc_bitmap_dup(process_cpuset));
    CpuSet* cpuset2 = new CpuSet(hwloc_bitmap_dup(process_cpuset));
    ThreadConfig tc;

    std::shared_ptr<NumaWrapperMock> numa_mock = std::make_shared<NumaWrapperMock>();
    std::shared_ptr<HwlocWrapperMock> hwloc_mock = std::make_shared<HwlocWrapperMock>();

    hwloc_mock->node.os_index = 0;

    numa = numa_mock;
    hwloc = hwloc_mock;

    tc.set_thread_affinity(STHREAD_TYPE_PACKET, 0, cpuset2);
    tc.set_thread_affinity(STHREAD_TYPE_PACKET, 1, cpuset);

    CHECK(true == tc.implement_thread_mempolicy(STHREAD_TYPE_PACKET, 0));

    hwloc_mock->node.os_index = 1;
    numa_mock->pref = 1;
    CHECK(true == tc.implement_thread_mempolicy(STHREAD_TYPE_PACKET, 1));
}

TEST_CASE("numa_available negative test", "[ThreadConfig]")
{
    CpuSet* cpuset = new CpuSet(hwloc_bitmap_dup(process_cpuset));
    ThreadConfig tc;
    tc.set_thread_affinity(STHREAD_TYPE_PACKET, 1, cpuset);

    std::shared_ptr<NumaWrapperMock> numa_mock = std::make_shared<NumaWrapperMock>();
    std::shared_ptr<HwlocWrapperMock> hwloc_mock = std::make_shared<HwlocWrapperMock>();

    numa_mock->numa_avail = -1;
    numa = numa_mock;
    hwloc = hwloc_mock;
    CHECK(false == tc.implement_thread_mempolicy(STHREAD_TYPE_PACKET, 0));
}

TEST_CASE("set node failure negative test", "[ThreadConfig]")
{
    CpuSet* cpuset = new CpuSet(hwloc_bitmap_dup(process_cpuset));
    ThreadConfig tc;
    tc.set_thread_affinity(STHREAD_TYPE_PACKET, 0, cpuset);

    std::shared_ptr<NumaWrapperMock> numa_mock = std::make_shared<NumaWrapperMock>();
    std::shared_ptr<HwlocWrapperMock> hwloc_mock = std::make_shared<HwlocWrapperMock>();
    hwloc_mock->node.os_index = 0;
    numa_mock->pref = -1;
    numa = numa_mock;
    hwloc = hwloc_mock;
    CHECK(false == tc.implement_thread_mempolicy(STHREAD_TYPE_PACKET, 0));
}

TEST_CASE("depth unknown negative test", "[ThreadConfig]")
{
    CpuSet* cpuset = new CpuSet(hwloc_bitmap_dup(process_cpuset));

    ThreadConfig tc;
    tc.set_thread_affinity(STHREAD_TYPE_PACKET, 0, cpuset);

    std::shared_ptr<NumaWrapperMock> numa_mock = std::make_shared<NumaWrapperMock>();
    std::shared_ptr<HwlocWrapperMock> hwloc_mock = std::make_shared<HwlocWrapperMock>();

    hwloc_mock->type_depth = HWLOC_TYPE_DEPTH_UNKNOWN;
    hwloc = hwloc_mock;
    numa = numa_mock;
    CHECK(false == tc.implement_thread_mempolicy(STHREAD_TYPE_PACKET, 0));
}

TEST_CASE("set memory policy failure negative test", "[ThreadConfig]")
{
    CpuSet* cpuset = new CpuSet(hwloc_bitmap_dup(process_cpuset));
    ThreadConfig tc;
    tc.set_thread_affinity(STHREAD_TYPE_PACKET, 0, cpuset);

    std::shared_ptr<NumaWrapperMock> numa_mock = std::make_shared<NumaWrapperMock>();
    std::shared_ptr<HwlocWrapperMock> hwloc_mock = std::make_shared<HwlocWrapperMock>();

    hwloc_mock->node.os_index = 0;
    numa_mock->mem_policy = -1;
    numa = numa_mock;
    hwloc = hwloc_mock;
    CHECK(false == tc.implement_thread_mempolicy(STHREAD_TYPE_PACKET, 0));
}

TEST_CASE("get_nbobjs_by_depth failure negative test", "[ThreadConfig]")
{
    CpuSet* cpuset = new CpuSet(hwloc_bitmap_dup(process_cpuset));
    ThreadConfig tc;
    tc.set_thread_affinity(STHREAD_TYPE_PACKET, 0, cpuset);

    std::shared_ptr<NumaWrapperMock> numa_mock = std::make_shared<NumaWrapperMock>();
    std::shared_ptr<HwlocWrapperMock> hwloc_mock = std::make_shared<HwlocWrapperMock>();

    hwloc_mock->nbobjs_by_depth = 0;
    hwloc = hwloc_mock;
    numa = numa_mock;
    CHECK(false == tc.implement_thread_mempolicy(STHREAD_TYPE_PACKET, 0));
}

#endif

#endif
