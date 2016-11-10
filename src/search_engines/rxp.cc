//--------------------------------------------------------------------------
// Copyright (C) 2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2016 Titan IC Systems. All rights reserved.
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

// rxp.cc author Titan IC Systems <support@titanicsystems.com>

#include <assert.h>
#include <ctype.h>
#include <string.h>

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <rte_config.h>
#include <rte_eal.h>
#include <rxp.h>
#include <rxp_errors.h>

#include "framework/mpse.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "utils/stats.h"

// FIXIT-T: We should determine a sensible number for this, to keep a max limit if necessary.
#define RXP_MAX_JOBS        128 // Max jobs expected per packet
#define RXP_MAX_SUBSETS     4   // Hardware supports max 4 at once
#define RXP_PACKET_LENGTH   64  // Minimum data size to perform match with RXP

using namespace std;

// Escape a pattern to a form suitable for feeding to the RXP compiler.
// Anything non-printable is represented as \x<value>. Caller must free
// returned string.
static string* rxp_escape_pattern(const uint8_t* pat, unsigned len)
{
    int i;
    string* escpat = nullptr;
    char hexbyte[5];

    if (len == 0)
        return nullptr;

    escpat = new string;

    for (i = 0; i < len; i++)
    {
        // Could be less strict; but 'if (pat[i] < 32 or pat[i] > 126)' is too loose
        if (!isalnum(pat[i]))
        {
            sprintf(hexbyte, "\\x%02x", pat[i]);
            escpat->append(hexbyte);
        }
        else
        {
            escpat->append(1, (const char) pat[i]);
        }
    }

    return escpat;
}

struct UserCtx {
    void *user;
    void *user_tree;
    void *user_list;

    UserCtx(void *u);
};

UserCtx::UserCtx(void *u)
{
    user = u;
    user_tree = user_list = nullptr;
}

struct RxpPattern
{
    std::string* pat;
    uint16_t ruleid;
    bool no_case;
    bool negate;

    vector<struct UserCtx> userctx;

    RxpPattern(string* pattern, const Mpse::PatternDescriptor& d, void *u);
    ~RxpPattern(void);
};

RxpPattern::RxpPattern(string* pattern, const Mpse::PatternDescriptor& d, void *u)
{
    pat = pattern;

    no_case = d.no_case;
    negate = d.negated;
    userctx.push_back(UserCtx(u));
}

RxpPattern::~RxpPattern(void)
{
    delete pat;
}

struct RxpJob
{
    uint32_t jobid;
    uint8_t* buf;
    unsigned int len;
    unsigned int offset;
    MpseMatch match_cb;
    void *match_ctx;

    int subset_count;
    class RxpMpse* subset[RXP_MAX_SUBSETS];

    RxpJob(const uint8_t* buf_n, int n, MpseMatch mf, void* pv);
    ~RxpJob(void);
};

RxpJob::RxpJob(const uint8_t* buf_n, int n, MpseMatch mf, void* pv)
{
    jobid = 0;
    buf = (uint8_t*) buf_n;
    len = n;
    offset = 0;
    match_cb = mf;
    match_ctx = pv;
}

RxpJob::~RxpJob(void)
{

}

//-------------------------------------------------------------------------
// mpse
//-------------------------------------------------------------------------

class RxpMpse : public Mpse
{
public:
    RxpMpse(SnortConfig*, bool use_gc, const MpseAgent* a)
        : Mpse("rxp", use_gc)
    {
        agent = a;
        instances.push_back(this);
        instance_id = instances.size();
    }

    ~RxpMpse()
    {
        user_dtor();
    }

    int add_pattern(
        SnortConfig*, const uint8_t* pat, unsigned len,
        const PatternDescriptor& desc, void* user) override;

    int prep_patterns(SnortConfig*) override;

    void _match(uint32_t ruleid, int to, MpseMatch mf, void *pv);
    int _search(const uint8_t*, int, MpseMatch, void*, int*) override;

    int get_pattern_count() override { return pats.size(); }

    int get_subset() { return instance_id; }

    static int write_rule_file(const string& filename);
    static int build_rule_file(const string& filename, const string& rulesdir);
    static int program_rule_file(const string& rulesdir);

    static int dpdk_init(void);

private:
    void user_ctor(SnortConfig*);
    void user_dtor();

    const MpseAgent* agent;

    map<int, RxpPattern*> ruleidtbl;    // Maps rule ids to pattern + user ctx.
    uint64_t instance_id;               // This is used as the RXP subset ID


public:
    vector<RxpPattern*> pats;
    static vector<RxpJob*> jobs;
    static int jobcount;

    static uint64_t duplicates;
    static uint64_t jobs_submitted;
    static uint64_t match_limit;
    static uint64_t patterns;
    static uint64_t max_pattern_len;
    static vector<RxpMpse*> instances;
    static unsigned portid;
};

uint64_t RxpMpse::duplicates = 0;
uint64_t RxpMpse::jobs_submitted = 0;
uint64_t RxpMpse::match_limit = 0;
uint64_t RxpMpse::patterns = 0;
uint64_t RxpMpse::max_pattern_len = 0;
vector<RxpMpse*> RxpMpse::instances;
unsigned RxpMpse::portid = 0;

vector<RxpJob*> RxpMpse::jobs;
int RxpMpse::jobcount = 0;

// We don't have an accessible FSM match state, so like Hyperscan we build a simple
// tree for each option. However the same pattern can be used for several rules, so
// each RXP match may result in multiple rules we need to pass back to the snort core.
void RxpMpse::user_ctor(SnortConfig* sc)
{
    unsigned i;

    for ( auto& p : pats )
    {
        for ( auto& c : p->userctx )
        {
            if ( c.user )
            {
                if ( p->negate )
                    agent->negate_list(c.user, &c.user_list);
                else
                    agent->build_tree(sc, c.user, &c.user_tree);
            }
            agent->build_tree(sc, nullptr, &c.user_tree);
        }
    }
}

void RxpMpse::user_dtor()
{
    unsigned i;

    for ( auto& p : pats )
    {
        for ( auto& c : p->userctx )
        {
            if ( c.user )
                agent->user_free(c.user);

            if ( c.user_list )
                agent->list_free(&c.user_list);

            if ( c.user_tree )
                agent->tree_free(&c.user_tree);
        }
    }
}

int RxpMpse::add_pattern(SnortConfig*, const uint8_t* pat, unsigned len,
    const PatternDescriptor& desc, void* user)
{
    RxpPattern* rxp_pat = nullptr;
    string* pattern = rxp_escape_pattern(pat, len);

    for ( auto& p : pats)
    {
        if (*p->pat == *pattern) {
            rxp_pat = p;
            break;
        }
    }

    if (rxp_pat)
    {
        // It's a duplicate pattern, record it so we can report back multiple matches
        rxp_pat->userctx.push_back(UserCtx(user));
        ++duplicates;
    }
    else
    {
        rxp_pat = new RxpPattern(pattern, desc, user);

        rxp_pat->ruleid = ++patterns;
        ruleidtbl[rxp_pat->ruleid] = rxp_pat;

        if (len > max_pattern_len)
            max_pattern_len = len;

        pats.push_back(rxp_pat);
    }

    return 0;
}

int RxpMpse::prep_patterns(SnortConfig* sc)
{
    user_ctor(sc);
    return 0;
}

void RxpMpse::_match(uint32_t ruleid, int to, MpseMatch mf, void *pv)
{
    RxpPattern *pat = ruleidtbl[ruleid];

    if (!pat)
        return;

    for ( auto& c : pat->userctx )
    {
        mf(c.user, c.user_tree, to, pv, c.user_list);
    }
}

int RxpMpse::_search(
    const uint8_t* buf, int n, MpseMatch mf, void* pv, int* current_state)
{
    int i;

    *current_state = 0;

    for (i = 0; i < jobcount; i++)
    {
        if (jobs[i]->buf == buf and jobs[i]->len == n and jobs[i]->match_cb == mf and
            jobs[i]->match_ctx == pv and jobs[i]->subset_count < RXP_MAX_SUBSETS)
        {
            break;
        }
    }

    if (i == RXP_MAX_JOBS)
    {
        LogMessage("ERROR: Max RXP job count of %d reached.\n", i);
        // FIXIT-T: We should either dispatch, or expand the job table here.
    }
    else if (i == jobcount)
    {
        jobcount++;

        RxpJob* job = nullptr;
        job = new RxpJob(buf, n, mf, pv);

        job->subset[0] = this;
        job->subset_count = 1;

        jobs.push_back(job);
    }
    else
    {
        jobs[i]->subset[jobs[i]->subset_count] = this;
        jobs[i]->subset_count++;
    }

    return 0;
}

// Functions relating to the generation of the RXP rules file

int RxpMpse::write_rule_file(const string& filename)
{
    ofstream rulesfile;
    unsigned int rule, subset;

    rulesfile.open(filename);

    rulesfile << "# TICS subsets file for Snort-3.0" << endl;

    for (subset = 0; subset < instances.size(); subset++)
    {
        rulesfile << "subset_id = " << subset + 1 << endl;

        for (vector<RxpPattern*>::iterator rule = instances[subset]->pats.begin();
            rule != instances[subset]->pats.end(); rule++)
        {
            rulesfile << (*rule)->ruleid << ", " << *(*rule)->pat << endl;
        }
    }

    rulesfile.close();

    return 0;
}

int RxpMpse::build_rule_file(const string& filename, const string& rulesdir)
{
    ostringstream rxpc_cmd_str;

    rxpc_cmd_str << "rxpc -f " << filename << " -o " << rulesdir << "/snort3 --ptpb 0 -F -i";

    if (system(rxpc_cmd_str.str().c_str()))
    {
        LogMessage("ERROR: failed to exec rxpc.\n");
        exit(-1);
    }

    return 0;
}

int RxpMpse::program_rule_file(const string& rulesdir)
{
    ostringstream rulesfile;

    rulesfile << rulesdir << "/snort3.rof";

    return rxp_program_rules_memories(portid, 0 /* queue id */, rulesfile.str().c_str());
}

int RxpMpse::dpdk_init(void)
{
    char *dpdk_argv[4];

    dpdk_argv[0] = strdup("snort");
    dpdk_argv[1] = strdup("-c");
    dpdk_argv[2] = strdup("1");
    dpdk_argv[3] = strdup("--");

    if (rte_eal_init(4, dpdk_argv) < 0)
    {
        LogMessage("ERROR: Failed to initialise DPDK EAL.\n");
        exit(-1);
    }

    if (rxp_port_init(portid, 1 /* num queues */, 1))
    {
        LogMessage("ERROR: Failed to initialise RXP port.\n");
        exit(-1);
    }

    if (rxp_init(portid))
    {
        LogMessage("ERROR: Failed to initialise RXP.\n");
        exit(-1);
    }

    return 0;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static void rxp_setup(SnortConfig* sc)
{
    // FIXIT-T: These file paths should be a configuration setting.
    RxpMpse::write_rule_file("/tmp/snort3.rules");
    RxpMpse::build_rule_file("/tmp/snort3.rules", "/tmp/snort-rof");

    RxpMpse::dpdk_init();
    RxpMpse::program_rule_file("/tmp/snort-rof");
    rxp_enable(RxpMpse::portid);
}

static Mpse* rxp_ctor(
    SnortConfig* sc, class Module*, bool use_gc, const MpseAgent* a)
{
    RxpMpse* instance;

    instance = new RxpMpse(sc, use_gc, a);

    return instance;
}

static void rxp_dtor(Mpse* p)
{
    delete p;
}

static void rxp_init()
{
    RxpMpse::jobs_submitted = 0;
    RxpMpse::match_limit = 0;
    RxpMpse::patterns = 0;
    RxpMpse::max_pattern_len = 0;
}

static void rxp_print()
{
    LogCount("instances", RxpMpse::instances.size());
    LogCount("patterns", RxpMpse::patterns);
    LogCount("duplicate patterns", RxpMpse::duplicates);
    LogCount("maximum pattern length", RxpMpse::max_pattern_len);
    LogCount("RXP jobs submitted", RxpMpse::jobs_submitted);
    LogCount("RXP match limit exceeded", RxpMpse::match_limit);
}

static void rxp_begin_packet()
{
    RxpMpse::jobcount = 0;
    RxpMpse::jobs.reserve(RXP_MAX_JOBS);
    RxpMpse::jobs.clear();
}

static int rxp_receive_responses()
{
    struct rte_mbuf* pkts_burst[RXP_MAX_PKT_BURST];
    struct rxp_response_data rxp_resp;
    int i, j, ret, processed = 0;
    unsigned rx_pkts = 0;
    RxpJob* job;

    ret = rxp_get_responses(RxpMpse::portid, 0 /* queue id */, pkts_burst,
        (RxpMpse::jobcount - processed), &rx_pkts);

    if (ret != RXP_STATUS_OK)
    {
        LogMessage("ERROR: %d rxp_get_responses() failed.\n", ret);
        /* FIXIT-T: We should fall back to a software search engine here.
         * For now keep going or throw an error and quit.*/
    }

    while (rx_pkts != 0)
    {
        ret = rxp_get_response_data(pkts_burst[--rx_pkts], &rxp_resp);

        if (ret != RXP_STATUS_OK)
        {
            LogMessage("ERROR: %d rxp_get_response_data() failed.\n", ret);
            /* FIXIT-T: We should fall back to a software search engine here.
             * For now keep going or throw an error and quit.*/
        }

        if (rxp_resp.match_count != 0)
        {
            if (rxp_resp.detected_match_count > rxp_resp.match_count)
            {
                LogMessage("WARNING: Detected %u matches but only %u returned.\n",
                    rxp_resp.detected_match_count, rxp_resp.match_count);
                RxpMpse::match_limit++;
                /* FIXIT-T: We should fall back to a software search engine here.
                 * For now keep going.*/
            }

            job = nullptr;
            for (i = 0; i < RxpMpse::jobcount; i++)
            {
                if (rxp_resp.job_id == RxpMpse::jobs[i]->jobid)
                {
                    job = RxpMpse::jobs[i];
                    break;
                }
            }

            if (!job)
            {
                LogMessage("ERROR: Got job response for unexpected job %u\n", rxp_resp.job_id);
                LogMessage("  Expected jobs are:");
                for (i = 0; i < RxpMpse::jobcount; i++)
                {
                    LogMessage(" %d", RxpMpse::jobs[i]->jobid);
                }
                LogMessage("\n");
            }
            else
            {
                for (i = 0; i < rxp_resp.match_count; i++)
                {
                    int to = job->offset + rxp_resp.match_data[i].start_ptr +
                        rxp_resp.match_data[i].length;

                    for (j = 0; j < job->subset_count; j++)
                    {
                        job->subset[j]->_match(rxp_resp.match_data[i].rule_id, to,
                            job->match_cb, job->match_ctx);
                    }
                }
            }
        }

        rxp_free_buffer(pkts_burst[rx_pkts]);
        processed++;
    }

    return processed;
}

static int rxp_send_jobs()
{
    struct rte_mbuf* job_buf;
    int i, j, ret, processed = 0;

    // Prepare all the jobs for this packet
    for (i = 0; i < RxpMpse::jobcount; i++)
    {
        // Buffer is larger than a single RXP job can be, split up and overlap
        if (RxpMpse::jobs[i]->len > RXP_MAX_JOB_LENGTH)
        {
            if (RxpMpse::jobcount == RXP_MAX_JOBS)
            {
                LogMessage("WARNING: No spare job slot to split job of %d bytes, "
                        "truncating to %d.\n",
                        RxpMpse::jobs[i]->len, RXP_MAX_JOB_LENGTH);
                RxpMpse::jobs[i]->len = RXP_MAX_JOB_LENGTH;
            }
            else
            {
                RxpJob* job = nullptr;
                job = new RxpJob(RxpMpse::jobs[i]->buf, RxpMpse::jobs[i]->len,
                        RxpMpse::jobs[i]->match_cb, RxpMpse::jobs[i]->match_ctx);

                job->subset_count = RxpMpse::jobs[i]->subset_count;

                for (j = 0; j < RXP_MAX_SUBSETS; j++)
                    job->subset[j] = RxpMpse::jobs[i]->subset[j];

                RxpMpse::jobs.push_back(job);

                RxpMpse::jobs[i]->len = RXP_MAX_JOB_LENGTH;
                RxpMpse::jobs[RxpMpse::jobcount]->offset =
                        (RXP_MAX_JOB_LENGTH - RxpMpse::max_pattern_len);
                RxpMpse::jobs[RxpMpse::jobcount]->len -=
                        (RXP_MAX_JOB_LENGTH - RxpMpse::max_pattern_len);
                RxpMpse::jobs[RxpMpse::jobcount]->buf +=
                        (RXP_MAX_JOB_LENGTH - RxpMpse::max_pattern_len);
                RxpMpse::jobcount++;
            }
        }

        RxpMpse::jobs[i]->jobid = ++RxpMpse::jobs_submitted; // Job ID can't be 0

        // Subset ID 0 is an error, so set any unused slots to the first subset
        for (j = 3; j >= RxpMpse::jobs[i]->subset_count; j--)
            RxpMpse::jobs[i]->subset[j] = RxpMpse::jobs[i]->subset[0];

        ret = rxp_prepare_job(RxpMpse::portid, RxpMpse::jobs[i]->jobid, RxpMpse::jobs[i]->buf,
            RxpMpse::jobs[i]->len, 0 /* ctrl */, RxpMpse::jobs[i]->subset[0]->get_subset(),
            RxpMpse::jobs[i]->subset[1]->get_subset(), RxpMpse::jobs[i]->subset[2]->get_subset(),
            RxpMpse::jobs[i]->subset[3]->get_subset(),
            &job_buf);

        if (ret != RXP_STATUS_OK)
        {
            LogMessage("ERROR: %d rxp_prepare_job() failed.\n", ret);
            /* FIXIT-T: We should fall back to a software search engine here.
             * For now keep going or throw an error and quit.*/
        }

        ret = rxp_enqueue_job(RxpMpse::portid, 0 /* queue id */, job_buf);

        /*Probable error due responses queue full*/
        if(ret == RXP_STATUS_ENQUEUE_JOB_FAILED)
        {
            /*  In this case we need to recover responses from RXP, process
             *  them (until no more responses), and re-try to enqueue,
             *  if another failure then is an RXP error.
             *
             *  Note the processed variable for the current version will
             *  have to be updated here.
             *  However, in non blocking version this would not be necessary*/

            unsigned temp_responses = processed;
            processed += rxp_receive_responses();
            while(processed > temp_responses)
            {
                temp_responses = processed;
                processed += rxp_receive_responses();
            }
            ret = rxp_enqueue_job(RxpMpse::portid, 0 /* queue id */, job_buf);
        }

        if (ret != RXP_STATUS_OK)
        {
            LogMessage("ERROR: %d rxp_enqueue_job() failed.\n", ret);
            /* FIXIT-T: We should fall back to a software search engine here.
             * For now keep going or throw an error and quit.*/
        }
    }

    return processed;
}

static void rxp_dispatch_jobs()
{
    int ret;
    unsigned sent, pending;

    // Submit all jobs in a single batch
    ret = rxp_dispatch_jobs(RxpMpse::portid, 0 /* queue id */, &sent, &pending);

    if (ret != RXP_STATUS_OK)
    {
        LogMessage("ERROR: %d rxp_dispatch_jobs() failed.\n", ret);
        exit(-1);
    }
}

static void rxp_end_packet()
{
    int processed = 0;

    if (RxpMpse::jobcount == 0)
        return; // Nothing to do.

    // Prepare and enqueue all the jobs for this packet
    processed = rxp_send_jobs();

    // Submit our enqueued Jobs
    rxp_dispatch_jobs();

    // Collect all jobs responses
    while (processed < RxpMpse::jobcount)
    {
        processed += rxp_receive_responses();
    }

    return;
}

static const MpseApi rxp_api =
{
    {
        PT_SEARCH_ENGINE,
        sizeof(MpseApi),
        SEAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        "rxp",
        "Titan IC Systems RXP-based hardware acclerated regex mpse",
        nullptr,
        nullptr
    },
    false,
    nullptr,
    rxp_setup,
    nullptr,  // start
    nullptr,  // stop
    rxp_ctor,
    rxp_dtor,
    rxp_init,
    rxp_print,
    rxp_begin_packet,
    rxp_end_packet,
};

const BaseApi* se_rxp = &rxp_api.base;
