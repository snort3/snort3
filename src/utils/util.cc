//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 2002 Martin Roesch <roesch@sourcefire.com>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "util.h"

#include <fcntl.h>
#include <grp.h>
#include <luajit.h>
#include <netdb.h>
#include <openssl/crypto.h>
#include <pcap.h>
#include <pcre.h>
#include <pwd.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <zlib.h>

#ifdef HAVE_HYPERSCAN
#include <hs_compile.h>
#endif

#ifdef HAVE_LZMA
#include <lzma.h>
#endif

#ifdef HAVE_LIBML
#include <libml.h>
#endif

extern "C" {
#include <daq.h>
}

#include <chrono>
#include <fstream>
#include <random>

#include "log/messages.h"
#include "main/snort_config.h"
#include "packet_io/sfdaq.h"
#include "protocols/packet.h"   // For NUM_IP_PROTOS

#include "util_cstring.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

#ifdef _WIN32
#define STAT _stat
#else
#define STAT stat
#endif

#ifdef _WIN32
#define ISREG(m) (((m) & _S_IFMT) == _S_IFREG)
#else
#define ISREG(m) S_ISREG(m)
#endif

using namespace snort;

/****************************************************************************
 * Store interesting data in memory that would not otherwise be visible
 * in a CORE(5) file
 ***************************************************************************/
#ifdef BUILD
    #define SNORT_VERSION_STRING ("### Snort Version " VERSION " Build " BUILD "\n")
#else
    #define SNORT_VERSION_STRING ("### Snort Version " VERSION "\n")
#endif
#define SNORT_VERSION_STRLEN sizeof(SNORT_VERSION_STRING)
char __snort_version_string[SNORT_VERSION_STRLEN];

void StoreSnortInfoStrings()
{
    strncpy(__snort_version_string, SNORT_VERSION_STRING,
        sizeof(__snort_version_string));
}

#undef SNORT_VERSION_STRING
#undef SNORT_VERSION_STRLEN

int DisplayBanner()
{
    const char* ljv = LUAJIT_VERSION;
    while ( *ljv && !isdigit(*ljv) )
        ++ljv;

    LogMessage("\n");
    LogMessage("   ,,_     -*> Snort++ <*-\n");
#ifdef BUILD
    LogMessage("  o\"  )~   Version %s (Build %s)\n", VERSION, BUILD);
#else
    LogMessage("  o\"  )~   Version %s\n", VERSION);
#endif
    LogMessage("   ''''    By Martin Roesch & The Snort Team\n");
    LogMessage("           http://snort.org/contact#team\n");
    LogMessage("           Copyright (C) 2014-2024 Cisco and/or its affiliates."
                           " All rights reserved.\n");
    LogMessage("           Copyright (C) 1998-2013 Sourcefire, Inc., et al.\n");
    LogMessage("           Using DAQ version %s\n", daq_version_string());
    LogMessage("           Using LuaJIT version %s\n", ljv);
    LogMessage("           Using %s\n", OpenSSL_version(SSLEAY_VERSION));
    LogMessage("           Using %s\n", pcap_lib_version());
    LogMessage("           Using PCRE version %s\n", pcre_version());
    LogMessage("           Using ZLIB version %s\n", zlib_version);
#ifdef HAVE_HYPERSCAN
    LogMessage("           Using Hyperscan version %s\n", hs_version());
#endif
#ifdef HAVE_LZMA
    LogMessage("           Using LZMA version %s\n", lzma_version_string());
#endif
#ifdef HAVE_LIBML
    LogMessage("           Using LibML version %s\n", libml_version());
#endif
    LogMessage("\n");

    return 0;
}

// get offset seconds from GMT
int gmt2local(time_t t)
{
    if (t == 0)
        t = time(nullptr);

    struct tm gmt;
    struct tm* lt = gmtime_r(&t, &gmt);
    if (lt == nullptr)
        return 0;

    struct tm loc;
    localtime_r(&t, &loc);

    int dt = (loc.tm_hour - gmt.tm_hour) * 60 * 60 +
        (loc.tm_min - gmt.tm_min) * 60;

    int dir = loc.tm_year - gmt.tm_year;

    if (dir == 0)
        dir = loc.tm_yday - gmt.tm_yday;

    dt += dir * 24 * 60 * 60;

    return(dt);
}

static FILE* pid_lockfile = nullptr;
static FILE* pid_file = nullptr;

void CreatePidFile(pid_t pid)
{
    SnortConfig* sc = SnortConfig::get_main_conf();

    sc->pid_filename = sc->log_dir;
    sc->pid_filename += "/snort.pid";

    std::string pid_lockfilename;

    if ( !sc->no_lock_pid_file() )
    {
        pid_lockfilename = sc->pid_filename;
        pid_lockfilename += ".lck";

        /* First, lock the PID file */
        pid_lockfile = fopen(pid_lockfilename.c_str(), "w");

        if ( pid_lockfile )
        {
            struct flock lock;
            int lock_fd = fileno(pid_lockfile);

            lock.l_type = F_WRLCK;
            lock.l_whence = SEEK_SET;
            lock.l_start = 0;
            lock.l_len = 0;

            if (fcntl(lock_fd, F_SETLK, &lock) == -1)
            {
                ClosePidFile();
                ParseError("Failed to Lock PID File \"%s\" for PID \"%d\"",
                    sc->pid_filename.c_str(), (int)pid);
                return;
            }
        }
    }

    /* Okay, were able to lock PID file, now open and write PID */
    pid_file = fopen(sc->pid_filename.c_str(), "w");
    if (pid_file)
    {
        LogMessage("Writing PID \"%d\" to file \"%s\"\n", (int)pid,
            sc->pid_filename.c_str());
        fprintf(pid_file, "%d\n", (int)pid);
        fflush(pid_file);
    }
    else
    {
        if (pid_lockfile)
        {
            fclose(pid_lockfile);
            pid_lockfile = nullptr;
        }
        const char* error = get_error(errno);
        ErrorMessage("Failed to create pid file %s, Error: %s\n",
            sc->pid_filename.c_str(), error);
        sc->pid_filename.clear();
    }
    if ( !pid_lockfilename.empty() )
        unlink(pid_lockfilename.c_str());
}

void ClosePidFile()
{
    if (pid_file)
    {
        fclose(pid_file);
        pid_file = nullptr;
    }
    if (pid_lockfile)
    {
        fclose(pid_lockfile);
        pid_lockfile = nullptr;
    }
}

// set safe UserID and GroupID, if needed
bool SetUidGid(int user_id, int group_id)
{
    // Were any changes requested?
    if (group_id == -1 && user_id == -1)
        return true;

    if (group_id != -1)
    {
        if (setgid(group_id) < 0)
        {
            ParseError("Cannot set GID: %d", group_id);
            return false;
        }
        LogMessage("Set GID to %d\n", group_id);
    }

    if (user_id != -1)
    {
        if (setuid(user_id) < 0)
        {
            ParseError("Cannot set UID: %d", user_id);
            return false;
        }
        LogMessage("Set UID to %d\n", user_id);
    }

    return true;
}

// set the groups of the process based on the UserID with the GroupID added
void InitGroups(int user_id, int group_id)
{
    if ((user_id != -1) && (getuid() == 0))
    {
        struct passwd* pw = getpwuid(user_id);  // main thread only

        if (pw != nullptr)
        {
            /* getpwuid and initgroups may use the same static buffers */
            char* username = snort_strdup(pw->pw_name);

            if (initgroups(username, group_id) < 0)
                ParseError("Can not initgroups(%s,%d)", username, group_id);

            snort_free(username);
        }

        /** Just to be on the safe side... **/
        endgrent();
        endpwent();
    }
}

//-------------------------------------------------------------------------

// FIXIT-L this is a duplicate of PacketManager::get_proto_name()
void InitProtoNames()
{
    if ( !protocol_names )
        protocol_names = (char**)snort_calloc(NUM_IP_PROTOS, sizeof(char*));

    for ( int i = 0; i < NUM_IP_PROTOS; i++ )
    {
        struct protoent* pt = getprotobynumber(i);  // main thread only

        if (pt != nullptr)
        {
            protocol_names[i] = snort_strdup(pt->p_name);

            for ( size_t j = 0; j < strlen(protocol_names[i]); j++ )
                protocol_names[i][j] = toupper(protocol_names[i][j]);
        }
        else
        {
            char protoname[10];
            SnortSnprintf(protoname, sizeof(protoname), "PROTO:%03d", i);
            protocol_names[i] = snort_strdup(protoname);
        }
    }
}

void CleanupProtoNames()
{
    if (protocol_names != nullptr)
    {
        int i;

        for (i = 0; i < NUM_IP_PROTOS; i++)
        {
            if (protocol_names[i] != nullptr)
                snort_free(protocol_names[i]);
        }

        snort_free(protocol_names);
        protocol_names = nullptr;
    }
}

// read the BPF filters in from a file, return the processed BPF string
std::string read_infile(const char* key, const char* fname)
{
    int fd = open(fname, O_RDONLY);
    struct stat buf;

    if (fd < 0)
    {
        ErrorMessage("Failed to open file: %s with error: %s", fname, get_error(errno));
        return "";
    }

    if (fstat(fd, &buf) < 0)
    {
        ParseError("can't stat %s: %s", fname, get_error(errno));
        close(fd);
        return "";
    }

    //check that its a regular file and not a directory or special file
    if (!S_ISREG(buf.st_mode) )
    {
        ParseError("not a regular file: %s", fname);
        close(fd);
        return "";
    }

    std::string line;
    std::ifstream bpf_file(fname);

    if (bpf_file.is_open())
    {
        std::stringstream file_content;
        file_content << bpf_file.rdbuf();
        line = file_content.str();

        bpf_file.close();
    }
    else
    {
        ParseError("can't open file %s = %s: %s", key, fname, get_error(errno));
        close(fd);
        return "";
    }
    close(fd);
    return line;
}

typedef char PathBuf[PATH_MAX+1];

static const char* CurrentWorkingDir(PathBuf& buf)
{
    if ( !getcwd(buf, sizeof(buf)-1) )
        return nullptr;

    buf[sizeof(buf)-1] = '\0';
    return buf;
}

static char* GetAbsolutePath(const char* dir, PathBuf& buf)
{
    assert(dir);
    errno = 0;

    if ( !realpath(dir, buf) )
    {
        LogMessage("Couldn't determine absolute path for '%s': %s\n", dir, get_error(errno));
        return nullptr;
    }

    return buf;
}

// Chroot and adjust the log_dir reference
bool EnterChroot(std::string& root_dir, std::string& log_dir)
{
    if (log_dir.empty())
    {
        ParseError("Log directory not specified");
        return false;
    }
    PathBuf pwd;
    PathBuf abs_log_dir;

    if ( !GetAbsolutePath(log_dir.c_str(), abs_log_dir) )
        return false;

    /* change to the desired root directory */
    if (chdir(root_dir.c_str()) != 0)
    {
        ParseError("EnterChroot: Can not chdir to \"%s\": %s", root_dir.c_str(),
            get_error(errno));
        return false;
    }

    /* always returns an absolute pathname */
    const char* abs_root_dir = CurrentWorkingDir(pwd);
    if (!abs_root_dir)
    {
        ParseError("Couldn't retrieve current working directory");
        return false;
    }
    size_t abs_root_dir_len = strlen(abs_root_dir);

    if (strncmp(abs_root_dir, abs_log_dir, abs_root_dir_len))
    {
        ParseError("Specified log directory is not contained with the chroot jail");
        return false;
    }

    if (chroot(abs_root_dir) < 0)
    {
        ParseError("Can not chroot to \"%s\": absolute: %s: %s",
            root_dir.c_str(), abs_root_dir, get_error(errno));
        return false;
    }


    /* Immediately change to the root directory of the jail. */
    if (chdir("/") < 0)
    {
        ParseError("Can not chdir to \"/\" after chroot: %s",
            get_error(errno));
        return false;
    }


    if (abs_root_dir_len >= strlen(abs_log_dir))
        log_dir = "/";
    else
        log_dir = abs_log_dir + abs_root_dir_len;


    LogMessage("Chroot directory = %s\n", root_dir.c_str());

    return true;
}

unsigned int get_random_seed()
{
    unsigned int seed;

    try {
        seed = std::random_device{}();
    } catch ( const std::exception& ) {
        seed = std::chrono::system_clock::now().time_since_epoch().count();
    }

    return seed;
}

bool get_file_size(const std::string& path, size_t& size)
{
    struct STAT sb;

    if (STAT(path.c_str(), &sb))
        return false;

    if (!ISREG(sb.st_mode))
        return false;

    if (sb.st_size < 0)
        return false;

    size = static_cast<size_t>(sb.st_size);
    return true;
}

void StrToIntVector(const std::string& s, char delim, std::vector<uint32_t>& elems)
{
    std::istringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim))
    {
        size_t pos;
        uint32_t i = std::stoul(item, &pos);
        elems.push_back(i);
    }
}

std::string IntVectorToStr(const std::vector<uint32_t>& elems, char delim)
{
    std::string str = "none";
    if (elems.size())
    {
        std::ostringstream oss;
        for (size_t i = 0; i < elems.size(); ++i)
        {
            oss << elems[i];
            if (i < elems.size() - 1)
                oss << delim;
        }
        str = oss.str();
    }

    return str;
}

#if defined(NOCOREFILE)
void SetNoCores()
{
    struct rlimit rlim;

    getrlimit(RLIMIT_CORE, &rlim);
    rlim.rlim_max = 0;
    setrlimit(RLIMIT_CORE, &rlim);
}
#endif

namespace snort
{
char** protocol_names = nullptr;

const char* get_error(int errnum)
{
    static THREAD_LOCAL char buf[128];

#if defined(HAVE_GNU_STRERROR_R)
    return strerror_r(errnum, buf, sizeof(buf));
#else
    (void)strerror_r(errnum, buf, sizeof(buf));
    return buf;
#endif
}

char* snort_strndup(const char* src, size_t n)
{
    char* dst = (char*)snort_calloc(n + 1);
    return strncpy(dst, src, n);
}

char* snort_strdup(const char* str)
{
    assert(str);
    size_t n = strlen(str) + 1;
    char* p = (char*)snort_alloc(n);
    memcpy(p, str, n);
    return p;
}

void ts_print(const struct timeval* tvp, char* timebuf, bool yyyymmdd)
{
    struct timeval tv;
    struct timezone tz;

    // if null was passed, use current time
    if (!tvp)
    {
        // manual page (for linux) says tz is never used, so..
        memset((char*)&tz, 0, sizeof(tz));
        gettimeofday(&tv, &tz);
        tvp = &tv;
    }

    const SnortConfig* sc = SnortConfig::get_conf();
    int localzone = sc->thiszone;

    // If we're doing UTC, then make sure that the timezone is correct.
    if (sc->output_use_utc())
        localzone = 0;

    int s = (tvp->tv_sec + localzone) % SECONDS_PER_DAY;
    time_t Time = (tvp->tv_sec + localzone) - s;

    struct tm ttm;
    struct tm* lt = gmtime_r(&Time, &ttm);

    if ( !lt )
    {
        (void)SnortSnprintf(timebuf, TIMEBUF_SIZE, "%lu", tvp->tv_sec);

    }
    else if (sc->output_include_year())
    {
        int year = (lt->tm_year >= 100) ? (lt->tm_year - 100) : lt->tm_year;

        (void)SnortSnprintf(timebuf, TIMEBUF_SIZE,
            "%02d/%02d/%02d-%02d:%02d:%02d.%06u",
            year, lt->tm_mon + 1, lt->tm_mday,
            s / 3600, (s % 3600) / 60, s % 60,
            (unsigned)tvp->tv_usec);
    }
    else if (yyyymmdd)
    {
        (void)SnortSnprintf(timebuf, TIMEBUF_SIZE,
            "%04d-%02d-%02d %02d:%02d:%02d.%06u",
            lt->tm_year + 1900, lt->tm_mon + 1, lt->tm_mday,
            s / 3600, (s % 3600) / 60, s % 60,
            (unsigned)tvp->tv_usec);
    }
    else
    {
        (void)SnortSnprintf(timebuf, TIMEBUF_SIZE,
            "%02d/%02d-%02d:%02d:%02d.%06u", lt->tm_mon + 1,
            lt->tm_mday, s / 3600, (s % 3600) / 60, s % 60,
            (unsigned)tvp->tv_usec);
    }
}

static void start_hex_state(bool& hex_state, std::string& print_str)
{
    if (!hex_state)
    {
        hex_state = true;
        print_str += "|";
    }
}

static void end_hex_state(bool& hex_state, std::string& print_str)
{
    if (hex_state)
    {
        hex_state = false;
        print_str += "|";
    }
}

void uint8_to_printable_str(const uint8_t* buff, unsigned len, std::string& print_str)
{
    print_str.clear();
    char output[4];
    bool hex_state = false;
    for (unsigned i = 0 ; i < len ; i++)
    {
        if ((buff[i] >= 0x20) && (buff[i] <= 0x7E))
        {
            end_hex_state(hex_state, print_str);
            sprintf(output, "%c", (char)buff[i]);
        }
        else
        {
            start_hex_state(hex_state, print_str);
            sprintf(output, "%.2x ", buff[i]);
        }

        print_str += output;
    }

    end_hex_state(hex_state, print_str);
}

}

#ifdef UNIT_TEST
TEST_CASE("gmt2local_time_out_of_range", "[util]")
{
    REQUIRE((gmt2local(0xffffffff1fff2f)==0));
}

TEST_CASE("uint8_to_printable_str go over all options", "[util]")
{
    std::string print_str;
    uint8_t pattern[] = { 0, 'a', '(', 'd', ')', 1, '\r', 2, '\n','n'};
    uint8_to_printable_str(pattern, 10, print_str);
    CHECK((strcmp(print_str.c_str(),"|00 |a(d)|01 0d 02 0a |n") == 0));
}

TEST_CASE("uint8_to_printable_str empty buffer", "[util]")
{
    std::string print_str;
    uint8_t* pattern = nullptr;
    uint8_to_printable_str(pattern, 0, print_str);
    CHECK((strcmp(print_str.c_str(),"") == 0));
}

TEST_CASE("uint8_to_printable_str end with |", "[util]")
{
    std::string print_str;
    uint8_t pattern[] = { 'a', 0 };
    uint8_to_printable_str(pattern, 2, print_str);
    CHECK((strcmp(print_str.c_str(),"a|00 |") == 0));
}

#endif
