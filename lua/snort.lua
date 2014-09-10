---------------------------------------------------------------------------
-- Snort++ prototype configuration
--
-- let install_dir be a variable indicating where you installed Snort++.
-- then do:
--
-- export LUA_PATH=$install_dir/include/snort/lua/?.lua\;\;
-- export SNORT_LUA_PATH=$install_dir/conf/
---------------------------------------------------------------------------

require('snort_config')  -- for loading

-- useful constants
K = 1024
M = K * K
G = M * K

---------------------------------------------------------------------------
-- Set paths, ports, and nets:
--
-- variables with 'PATH' in the name are vars
-- variables with 'PORT' in the name are portvars
-- variables with 'NET' in the name are ipvars
-- variables with 'SERVER' in the name are ipvars
---------------------------------------------------------------------------

---------------------------------------------------------------------------
-- paths
---------------------------------------------------------------------------
-- Path to your rules files (this can be a relative path)

RULE_PATH = '../rules'
BUILTIN_RULE_PATH = '../preproc_rules'
PLUGIN_RULE_PATH = '../so_rules'

-- If you are using reputation preprocessor set these
WHITE_LIST_PATH = '../lists'
BLACK_LIST_PATH = '../lists'

---------------------------------------------------------------------------
-- networks
---------------------------------------------------------------------------
-- Setup the network addresses you are protecting
HOME_NET = 'any'

-- Set up the external network addresses. Leave as "any" in most situations
EXTERNAL_NET = 'any'

-- List of DNS servers on your network 
DNS_SERVERS = HOME_NET

-- List of SMTP servers on your network
SMTP_SERVERS = HOME_NET

-- List of web servers on your network
HTTP_SERVERS = HOME_NET

-- List of sql servers on your network 
SQL_SERVERS = HOME_NET

-- List of telnet servers on your network
TELNET_SERVERS = HOME_NET

-- List of ssh servers on your network
SSH_SERVERS = HOME_NET

-- List of ftp servers on your network
FTP_SERVERS = HOME_NET

-- List of sip servers on your network
SIP_SERVERS = HOME_NET

-- other variables, these should not be modified
AIM_SERVERS =
[[
64.12.24.0/23
64.12.28.0/23
64.12.161.0/24
64.12.163.0/24
64.12.200.0/24
205.188.3.0/24
205.188.5.0/24
205.188.7.0/24
205.188.9.0/24
205.188.153.0/24
205.188.179.0/24
205.188.248.0/24
]]

---------------------------------------------------------------------------
-- ports
---------------------------------------------------------------------------
-- List of ports you run web servers on
HTTP_PORTS =
[[
    80 81 311 383 591 593 901 1220 1414 1741 1830 2301 2381 2809 3037 3128
    3702 4343 4848 5250 6988 7000 7001 7144 7145 7510 7777 7779 8000 8008
    8014 8028 8080 8085 8088 8090 8118 8123 8180 8181 8243 8280 8300 8800
    8888 8899 9000 9060 9080 9090 9091 9443 9999 11371 34443 34444 41080
    50002 55555 
]]

-- List of ports you want to look for SHELLCODE on.
SHELLCODE_PORTS = ' !80'

-- List of ports you might see oracle attacks on
ORACLE_PORTS = ' 1024:'

-- List of ports you want to look for SSH connections on:
SSH_PORTS = ' 22'

-- List of ports you run ftp servers on
FTP_PORTS = ' 21 2100 3535'

-- List of ports you run SIP servers on
SIP_PORTS = ' 5060 5061 5600'

MAIL_PORTS = ' 110 143'

-- List of file data ports for file inspection
FILE_DATA_PORTS = HTTP_PORTS .. MAIL_PORTS

-- List of GTP ports for GTP preprocessor
GTP_PORTS = ' 2123 2152 3386'

RPC_PORTS = 
    ' 111 32770 32771 32772 32773 32774 32775 32776 32777 32778 32779'

---------------------------------------------------------------------------
-- configure builtin features
---------------------------------------------------------------------------

cd_udp = { gtp_ports = GTP_PORTS }

-- Configure active response for non inline operation.
active =
{
    --device = 'eth0',
    attempts = 0,
    max_responses = 1,
    min_interval = 1
}

-- Configure DAQ related options for inline operation.
-- <name> ::= pcap | afpacket | dump | nfq | ipq | ipfw
-- <mode> ::= read_file | passive | inline
-- <var> ::= arbitrary <name>=<value passed to DAQ
-- <dir> ::= path to DAQ module so's
daq =
{
    --name = 'dump',
    --var = { <var> }
}

-- Configure PCRE match limits
limit = 750

detection = 
{
    pcre_match_limit = 3 * limit,
    pcre_match_limit_recursion = limit
}

log_limit = 4

-- Configure the detection engine
search_engine =
{
    search_method = 'ac_bnfa_q',
    split_any_any = true,
    max_queue_events = 4 * log_limit
}

-- Configure the event queue.
event_queue =
{
    max_queue = 16,
    log = 16,
    order_events = 'priority'
}

-- Per packet and rule latency enforcement
ppm =
{
-- Per Packet latency configuration
    max_pkt_time = 0,
    fastpath_expensive_packets = true,
    pkt_log = 'log',

-- Per Rule latency configuration
    max_rule_time = 0,
    threshold = 3,
    suspend_expensive_rules = true,
    suspend_timeout = 20,
    rule_log = 'alert'
}

-- Configure Perf Profiling for debugging
profile =
{
    rules = { count = 0, sort = 'avg_ticks' },
    modules = { count = 0, sort = 'avg_ticks' }
}

---------------------------------------------------------------------------
-- configure inspectors
---------------------------------------------------------------------------

normalize =
{ 
    ip4 = 
    {
        base = true, df = true, rf = true, tos = true, trim = false
    },
    tcp =
    {
        base = true, ips = true, urp = true, trim = false, 
        ecn = 'stream', opts = true, 
        allow_codes = '123 224',
        allow_names = 'sack echo partial_order conn_count alt_checksum md5'
    },
    ip6 = true,
    icmp4 = true,
    icmp6 = true
}

arp_spoof =
{
    hosts =
    {
        { ip = '192.168.40.1', mac = 'f0:0f:00:f0:0f:00' },
        { ip = '192.168.40.2', mac = '0f:f0:00:0f:f0:00' }
    }
}

back_orifice = { }

rpc_decode = { }

port_scan_global = { memcap = 10000000 }

port_scan =
{
    protos = 'all',
    scan_types = 'all',
    sense_level = 'low',
    watch_ip = '![1.2.3.4]',
    ignore_scanners = '2.3.4.5/24',
    ignore_scanned = '4.5.6.7/8 9-10',
    include_midstream = true,
}

perf_monitor =
{
    packets = 10101,
    seconds = 60,
    reset = true,

    max_file_size = 2147483648,

    --max = true, -- max data output only to console?
    --console = true,

    -- everything should go to fixed name file in instance dir
    -- remove _file options and keep prefix to enable file or not
    --file = true,
    --events = true,
    flow = true,
    flow_file = true,
    --flow_ip = true,
    --flow_ip_file = true,
    --flow_ip_memcap = 52428800
}

---------------------------------------------------------------------------
-- http normalization and anomaly detection
---------------------------------------------------------------------------

default_http_methods =
[[
    GIT GET POST PUT SEARCH MKCOL COPY MOVE LOCK UNLOCK NOTIFY POLL BCOPY
    BDELETE BMOVE LINK UNLINK OPTIONS HEAD DELETE TRACE TRACK CONNECT
    SOURCE SUBSCRIBE UNSUBSCRIBE PROPFIND PROPPATCH BPROPFIND BPROPPATCH
    RPC_CONNECT PROXY_SUCCESS BITS_POST CCM_POST SMS_POST RPC_IN_DATA
    RPC_OUT_DATA RPC_ECHO_DATA
]]

http_inspect =
{
    --unicode_map =
    --{
    --    map_file = '/etc/unicode.map',
    --    code_page = 1252
    --},
    compress_depth = 65535,
    decompress_depth = 65535
}

http_server =
{
    http_methods = default_http_methods,
    chunk_length = 500000,
    server_flow_depth = 0,
    client_flow_depth = 0,
    post_depth = 0,
}

hi_x =
{
    http_methods = default_http_methods,
    chunk_length = 500000,
    server_flow_depth = 1460,
    client_flow_depth = 1460,
    post_depth = 65495,
}

--nhttp_inspect = { }

---------------------------------------------------------------------------
-- ftp / telnet normalization and anomaly detection
---------------------------------------------------------------------------

telnet =
{
    encrypted_traffic = false,
    check_encrypted = true,
    ayt_attack_thresh = 20,
    normalize = true,
}

ftp_default_commands =
[[
    ABOR ACCT ADAT ALLO APPE AUTH CCC CDUP CEL CLNT CMD CONF CWD DELE ENC
    EPRT EPSV ESTA ESTP FEAT HELP LANG LIST LPRT LPSV MACB MAIL MDTM MIC
    MKD MLSD MLST MODE NLST NOOP OPTS PASS PASV PBSZ PORT PROT PWD QUIT
    REIN REST RETR RMD RNFR RNTO SDUP SITE SIZE SMNT STAT STOR STOU STRU
    SYST TEST TYPE USER XCUP XCRC XCWD XMAS XMD5 XMKD XPWD XRCP XRMD XRSQ
    XSEM XSEN XSHA1 XSHA256
]]

ftp_format_commands = 
[[ 
    ACCT ADAT ALLO APPE AUTH CEL CLNT CMD CONF CWD DELE ENC EPRT EPSV ESTP
    HELP LANG LIST LPRT MACB MAIL MDTM MIC MKD MLSD MLST MODE NLST OPTS
    PASS PBSZ PORT PROT REST RETR RMD RNFR RNTO SDUP SITE SIZE SMNT STAT
    STOR STRU TEST TYPE USER XCRC XCWD XMAS XMD5 XMKD XRCP XRMD XRSQ XSEM
    XSEN XSHA1 XSHA256
]]

ftp_server =
{
    def_max_param_len = 100,

    encrypted_traffic = false,
    check_encrypted = true,
    print_cmds = false,
    telnet_cmds = true,
    ignore_telnet_erase_cmds = true,
    ignore_data_chan = true,

    ftp_cmds = ftp_default_commands,
    chk_str_fmt = ftp_format_commands,

    cmd_validity =
    {
        { command = 'ABOR', length = 0 },
        { command = 'CCC', length = 0 },
        { command = 'CDUP', length = 0 },
        { command = 'ESTA', length = 0 },
        { command = 'FEAT', length = 0 },
        { command = 'LPSV', length = 0 },
        { command = 'NOOP', length = 0 },
        { command = 'PASV', length = 0 },
        { command = 'PWD', length = 0 },
        { command = 'QUIT', length = 0 },
        { command = 'REIN', length = 0 },
        { command = 'SYST', length = 0 },
        { command = 'XCUP', length = 0 },
        { command = 'XPWD', length = 0 },

        { command = 'APPE', length = 200 },
        { command = 'CMD', length = 200 },
        { command = 'HELP', length = 200 },
        { command = 'NLST', length = 200 },
        { command = 'RETR', length = 200 },
        { command = 'RNFR', length = 200 },
        { command = 'STOR', length = 200 },
        { command = 'STOU', length = 200 },
        { command = 'XMKD', length = 200 },

        { command = 'CWD', length = 256 },
        { command = 'RNTO', length = 256 },
        { command = 'SIZE', length = 512 },

        { command = 'ALLO', length = 200, format = '< int [ char R int ] >' },
        { command = 'PORT', length = 400, format = '< host_port >' },

        { command = 'EPSV', format = '< [ { char 12 | char A char L char L } ] >' },
        { command = 'MACB', format = '< string >' },
        { command = 'MDTM', format = '< [ date nnnnnnnnnnnnnn[.n[n[n]]] ] string >' },
        { command = 'MODE', format = '< char ASBCZ >' },
        { command = 'PROT', format = '< char CSEP >' },
        { command = 'STRU', format = '< char FRPO [ string ] >' },
        { command = 'TYPE', 
          format = '< { char AE [ char NTC ] | char I | char L [ number ] } >' }
    },
}

ftp_client =
{
    max_resp_len = 256,
    bounce = true,
    ignore_telnet_erase_cmds = true,
    telnet_cmds = true,

    bounce_to =
    {
        { address = '192.168.1.1', port = 12345 },
        { address = '192.168.144.120', port = 50010, last_port = 50020 }
    }
}

ftp_data = { }

---------------------------------------------------------------------------
-- stream reassembly and anomaly detection
---------------------------------------------------------------------------

stream =
{
    ip_cache = { max_sessions = 64000 },
    icmp_cache = { max_sessions = 0 },
    tcp_cache = { max_sessions = 256000, idle_timeout = 60 },
    udp_cache = { max_sessions = 128000, pruning_timeout = 30 },
}

stream_ip =
{
    session_timeout = 980,
    policy = 'windows', 
    max_overlaps = 10,
    max_frags = 8191,
    min_frag_length = 100
}

stream_icmp =
{
    session_timeout = 180,
}

stream_tcp =
{
    policy = 'windows',
    paf_max = 16384,

    session_timeout = 180,
    --require_3whs = -1,
    show_rebuilt_packets = false,

    flush_factor = 0,
    overlap_limit = 10,

    footprint = 0,
    reassemble_async = true,
    ignore_any_rules = false,
}

tcp_x =
{
    policy = 'linux',
    paf_max = 16384,
    session_timeout = 180,
}

stream_udp =
{
    session_timeout = 180,
    ignore_any_rules = false,
}

---------------------------------------------------------------------------
-- loggers
---------------------------------------------------------------------------

-- alerts + packets
--[[
unified2 =
{
    file = 'u2.log',
    limit = 128 * M,
    nostamp = true,
    mpls_event_types = true,
    vlan_event_types = true
}
--]]

-- text
--alert_syslog = { mode = 'LOG_AUTH LOG_ALERT' }
alert_fast = { }
--alert_full = { }
--alert_test = { file = 'alert.tsv' }
--alert_csv = { file = 'alert.csv' }

-- to use -A lualert, this must be configured
lualert = { args = "foo = 'bar'" }

-- pcap
--log_tcpdump = { file = 'snort++.pcap' }

---------------------------------------------------------------------------
-- actions
---------------------------------------------------------------------------

--react = { }
reject = { reset = 'both', control = 'network' }
rewrite = { }

---------------------------------------------------------------------------
-- ips rules and filters
---------------------------------------------------------------------------

dir = os.getenv('SNORT_LUA_PATH')

if ( not dir ) then
    dir = ''
end

dofile(dir .. 'classification.lua')
dofile(dir .. 'reference.lua')

default_rules =
[[
# snort-classic comments, includes, and rules with $VARIABLES
# (rules files support the same syntax)

# builtin rules
#include $BUILTIN_RULE_PATH/preprocessor.rules
#include $BUILTIN_RULE_PATH/decoder.rules
#include $BUILTIN_RULE_PATH/sensitive-data.rules

# text rules
#include $RULE_PATH/local.rules

# so rules
#include $PLUGIN_RULE_PATH/dos.rules

# no metadata:service:
#alert http ( sid:1; msg:"1"; content:"HTTP"; )
#alert http any -> 1.2.3.4 ( sid:2; msg:"2"; content:"HTTP"; )
#alert http any any -> 1.2.3.4 80 ( sid:3; msg:"3"; content:"HTTP"; )

#alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"BLACKLIST User-Agent known malicious    user agent - SAH Agent"; flow:to_server,established; content:"User-Agent|3A| SAH Agent"; metadata: policy balanced-ips drop, policy connectivity-ips drop, policy security-ips drop, service http;    classtype:misc-activity; sid:5808; rev:9;)

#alert tcp any any -> any 80 ( msg:"Sample rule for Snort++"; http_uri; content:"attack"; sid:1; )
#alert tcp any 80 -> any any ( msg:"Sample rule for Snort++"; http_header:Transfer-Encoding; content:"chunk"; sid:2; )
#alert tcp any 80 -> any any ( msg:"Sample rule for Snort++"; http_header; content:"chunk"; sid:3; )
#alert tcp any any -> any any ( msg:"Sample rule for Snort++"; content:"trigger"; sid:2; )

#alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"FILE-IDENTIFY Microsoft Windows Visual Basic script file download request"; metadata:service http; reference:url,en.wikipedia.org/wiki/Vbs; classtype:misc-activity; sid:18758; rev:8; soid:3|18758;)

alert tcp any any -> any 80 ( http_method; content:"GIT"; gid:1; sid:1000051)
#alert tcp any any -> any 80 ( sid:1; msg:"found!"; content:"GET", nocase; content:"bck"; )
#alert tcp any any -> any 80 ( sid:2; msg:"found!"; http_method; content:"GET"; )
#alert tcp any any -> any 80 ( sid:3; msg:"found!"; content:"GET"; find:"pat=' HTTP/1%.%d'" ; )
#alert tcp any any -> any any ( gid:123; sid:2; msg:"(stream_ip) Teardrop attack"; )
#rewrite tcp any any -> any 80 ( sid:9; msg:"found!"; content:"GET"; replace:"GIT"; )
]]

network =
{
    checksum_eval = 'all'
}

-- put classic rules and includes in the include file and/or rules string
ips =
{
    --include = '../test.rules',
    include = 'rules/active.rules',
    --rules = default_rules,
    --enable_builtin_rules = true
}

--[[
event_filter =
{
    { gid = 1, sid = 2, type = 'both', count = 1, seconds = 5 },
    { gid = 1, sid = 1, type = 'both', count = 1, seconds = 5 }
}
--]]

suppress =
{
    { gid = 116, sid = 408 },
    { gid = 116, sid = 412 },
    { gid = 116, sid = 414 },
}

---------------------------------------------------------------------------
-- net map attributes (replaces attribte table)
---------------------------------------------------------------------------

hosts = 
{
    {
        ip = '1.2.3.4',
        frag_policy = 'linux',
        tcp_policy = 'linux',
        services =
        {
            { name = 'ftp', proto = 'tcp', port = 21 },
            { name = 'smtp', proto = 'tcp', port = 25 },
            { name = 'http', proto = 'tcp', port = 80 }
        }
    },
    {
        ip = '2.4.6.8',
        frag_policy = 'windows',
        tcp_policy = 'windows',
        services =
        {
            { name = 'netbios', proto = 'tcp', port = 137 },
            { name = 'imap', proto = 'tcp', port = 143 },
        }
    }
}

---------------------------------------------------------------------------
-- prototype wizard
---------------------------------------------------------------------------

http_methods = { 'GIT', 'GET', 'POST', 'HEAD' } -- build from default_http_methods
ftp_commands = { 'USER' } -- add others
sip_methods = { 'INVITE', 'NOTIFY' } -- add others
isakmp_hex = { '?????????????????|01|', '?????????????????|10|' }

telnet_commands =
{
    '|FF F0|', '|FF F1|', '|FF F2|', '|FF F3|',
    '|FF F4|', '|FF F5|', '|FF F6|', '|FF F7|',
    '|FF F8|', '|FF F9|', '|FF FA|', '|FF FB|',
    '|FF FC|', '|FF FD|', '|FF FE|', '|FF FF|'
}

wizard =
{
    spells =
    {
        { service = 'ftp', proto = 'tcp', client_first = false,
          to_server = ftp_commands, to_client = { '220*FTP' } },

        { service = 'http', proto = 'tcp', client_first = true,
          to_server = http_methods, to_client = { 'HTTP/' } },

        { service = 'imap', proto = 'tcp', client_first = false,
          to_server = { 'LOGIN', 'AUTHENTICATE', 'STARTTLS' },
          to_client = { '**OK', '**BYE' } },

        { service = 'pop3', proto = 'tcp', client_first = false,
          to_server = { 'USER', 'APOP' },
          to_client = { '+OK', '-ERR' } },

        { service = 'sip', proto = 'tcp', client_first = true,
          to_server = sip_methods, to_client = { 'SIP/' } },

        { service = 'smtp', proto = 'tcp', client_first = false,
          to_server = { 'HELO', 'EHLO' },
          to_client = { '220*SMTP', '220*MAIL' } },

        { service = 'ssh', proto = 'tcp', client_first = true,
          to_server = { '*SSH' }, to_client = { '*SSH' } }
    },
    hexes =
    {
        { service = 'dcerpc', proto = 'tcp', client_first = true, 
          to_server = { '|05 00|' }, to_client = { '|05 00|' } },

        { service = 'dnp3', proto = 'tcp', client_first = true, 
          to_server = { '|05 64|' }, to_client = { '|05 64|' } },

        { service = 'isakmp',  proto = 'udp', client_first = true,
          to_server = isakmp_hex, to_client = isakmp_hex },
--[[
        { service = 'modbus', proto = 'tcp', client_first = true,
          to_server = { '??|0 0|' } },

        { service = 'rpc', proto = 'tcp', client_first = true,
          to_server = { '????|0 0 0 0 0 0 0 1|' },
          to_client = { '????|0 0 0 0 0 0 0 1|' } },
--]]
        { service = 'smb', proto = 'tcp', client_first = true,
          to_server = { '|FF|SMB' }, to_client = { '|FF|SMB' } },

        { service = 'smb', proto = 'udp', client_first = true,
          to_server = { '|FF|SMB' }, to_client = { '|FF|SMB' } },

        { service = 'ssl', proto = 'tcp', client_first = true,
          to_server = { '|16 03|' }, to_client = { '|16 03|' } },

        { service = 'telnet', proto = 'tcp', client_first = true,
          to_server = telnet_commands, to_client = telnet_commands },
    }
}

---------------------------------------------------------------------------
-- prototype bindings:
--
-- only need to specify non-default bindings
-- when: policy_id, vlans, nets, proto, ports, service
-- use: action | file | type,name | service
-- when: roles, days, times are tbd
--
-- binder is disabled by default (xbinder is unknown, not loaded)
-- service inspectors will be bound automatically if wizard is configured
-- if binder is configured, there are no defaults added
---------------------------------------------------------------------------

xbinder =
{
    { when = { proto = 'tcp', ports = 'any' }, use = { type = 'wizard' } },
    { when = { proto = 'udp', ports = 'any' }, use = { type = 'wizard' } },

    { when = { service = 'ftp-data' }, use = { type = 'ftp_data' } },
    { when = { service = 'ftp' }, use = { type = 'ftp_server' } },
    { when = { service = 'http' }, use = { type = 'http_server' } },
    { when = { service = 'sunrpc' }, use = { type = 'rpc_decode' } },
    { when = { service = 'telnet' }, use = { type = 'telnet' } },
}
 
