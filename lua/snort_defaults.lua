---------------------------------------------------------------------------
-- Snort++ defaults
--
-- include in your snort.lua with a dofile statement
-- after you set HOME_NET and EXTERNAL_NET
--
-- use these by assignment, eg
--     ftp_server = default_ftp_server
---------------------------------------------------------------------------

---------------------------------------------------------------------------
-- Set paths, ports, and nets:
--
-- variables with 'PATH' in the name are vars
-- variables with 'PORT' in the name are portvars
-- variables with 'NET' in the name are ipvars
-- variables with 'SERVER' in the name are ipvars
---------------------------------------------------------------------------

---------------------------------------------------------------------------
-- default paths
---------------------------------------------------------------------------
-- Path to your rules files (this can be a relative path)

RULE_PATH = '../rules'
BUILTIN_RULE_PATH = '../preproc_rules'
PLUGIN_RULE_PATH = '../so_rules'

-- If you are using reputation preprocessor set these
WHITE_LIST_PATH = '../lists'
BLACK_LIST_PATH = '../lists'

---------------------------------------------------------------------------
-- default networks
---------------------------------------------------------------------------

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
-- default ports
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
-- default ftp server
---------------------------------------------------------------------------

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

ftp_command_specs =
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
}

default_ftp_server =
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
    cmd_validity = ftp_command_specs
}

---------------------------------------------------------------------------
-- default http profiles
---------------------------------------------------------------------------

http_profile_default = 
{
    profile_type = 'default',
    server_flow_depth = 300,
    client_flow_depth = 300,
    post_depth = -1,
    chunk_length = 500000,
    ascii = true,
    multi_slash = true,
    directory = true,
    webroot = true,
    double_decode = true,
    u_encode = true,
    bare_byte = true,
    iis_unicode = true,
    iis_backslash = true,
    iis_delimiter = true,
    apache_whitespace = true,
    non_strict = true,
    normalize_utf = true,
    normalize_javascript = false,
    max_header_length = 0,
    max_headers = 0,
    max_spaces = 200,
    max_javascript_whitespaces = 200,
    whitespace_chars ='0x9 0xb 0xc 0xd'
}

http_profile_apache = 
{
    profile_type = 'apache',
    server_flow_depth = 300,
    client_flow_depth = 300,
    post_depth = -1,
    chunk_length = 500000,
    ascii = true,
    multi_slash = true,
    directory = true,
    webroot = true,
    utf_8 = true,
    apache_whitespace = true,
    non_strict = true,
    normalize_utf = true,
    normalize_javascript = false,
    max_header_length = 0,
    max_headers = 0,
    max_spaces = 200,
    max_javascript_whitespaces = 200,
    whitespace_chars ='0x9 0xb 0xc 0xd'
}

http_profile_iis = 
{
    profile_type = 'iis',
    server_flow_depth = 300,
    client_flow_depth = 300,
    post_depth = -1,
    chunk_length = 500000,
    ascii = true,
    multi_slash = true,
    directory = true,
    webroot = true,
    double_decode = false,
    u_encode = true,
    bare_byte = true,
    iis_unicode = true,
    iis_backslash = true,
    iis_delimiter = true,
    apache_whitespace = true,
    non_strict = true,
    normalize_utf = true,
    normalize_javascript = false,
    max_header_length = 0,
    max_headers = 0,
    max_spaces = 200,
    max_javascript_whitespaces = 200,
    whitespace_chars ='0x9 0xb 0xc 0xd'
}

http_profile_iis_40 = 
{
    profile_type = 'iis_40',
    server_flow_depth = 300,
    client_flow_depth = 300,
    post_depth = -1,
    chunk_length = 500000,
    ascii = true,
    multi_slash = true,
    directory = true,
    webroot = true,
    double_decode = true,
    u_encode = true,
    bare_byte = true,
    iis_unicode = true,
    iis_backslash = true,
    iis_delimiter = true,
    apache_whitespace = true,
    non_strict = true,
    normalize_utf = true,
    normalize_javascript = false,
    max_header_length = 0,
    max_headers = 0,
    max_spaces = 200,
    max_javascript_whitespaces = 200,
    whitespace_chars ='0x9 0xb 0xc 0xd'
}

http_profile_iis_50 = 
{
    profile_type = 'iis_50',
    server_flow_depth = 300,
    client_flow_depth = 300,
    post_depth = -1,
    chunk_length = 500000,
    ascii = true,
    multi_slash = true,
    directory = true,
    webroot = true,
    double_decode = true,
    u_encode = true,
    bare_byte = true,
    iis_unicode = true,
    iis_backslash = true,
    iis_delimiter = true,
    apache_whitespace = true,
    non_strict = true,
    normalize_utf = true,
    normalize_javascript = false,
    max_header_length = 0,
    max_headers = 0,
    max_spaces = 200,
    max_javascript_whitespaces = 200,
    whitespace_chars ='0x9 0xb 0xc 0xd'
}

---------------------------------------------------------------------------
-- default wizard
---------------------------------------------------------------------------

http_methods =  -- build from default_http_methods
{
    'GET', 'POST', 'PUT', 'SEARCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK',
    'NOTIFY', 'POLL', 'BCOPY', 'BDELETE', 'BMOVE', 'LINK', 'UNLINK', 'OPTIONS',
    'HEAD', 'DELETE', 'TRACE', 'TRACK', 'CONNECT', 'SOURCE', 'SUBSCRIBE',
    'UNSUBSCRIBE', 'PROPFIND', 'PROPPATCH', 'BPROPFIND', 'BPROPPATCH',
    'RPC_CONNECT', 'PROXY_SUCCESS', 'BITS_POST', 'CCM_POST', 'SMS_POST',
    'RPC_IN_DATA', 'RPC_OUT_DATA', 'RPC_ECHO_DATA'
}

ftp_commands =  -- build from ftp_default_commands
{
    'ABOR', 'ACCT', 'ADAT', 'ALLO', 'APPE', 'AUTH', 'CCC', 'CDUP', 'CEL',
    'CLNT', 'CMD', 'CONF', 'CWD', 'DELE', 'ENC', 'EPRT', 'EPSV', 'ESTA',
    'ESTP', 'FEAT', 'HELP', 'LANG', 'LIST', 'LPRT', 'LPSV', 'MACB', 'MAIL',
    'MDTM', 'MIC', 'MKD', 'MLSD', 'MLST', 'MODE', 'NLST', 'NOOP', 'OPTS',
    'PASS', 'PASV', 'PBSZ', 'PORT', 'PROT', 'PWD', 'QUIT', 'REIN', 'REST',
    'RETR', 'RMD', 'RNFR', 'RNTO', 'SDUP', 'SITE', 'SIZE', 'SMNT', 'STAT',
    'STOR', 'STOU', 'STRU', 'SYST', 'TEST', 'TYPE', 'USER', 'XCUP', 'XCRC',
    'XCWD', 'XMAS', 'XMD5', 'XMKD', 'XPWD', 'XRCP', 'XRMD', 'XRSQ', 'XSEM',
    'XSEN', 'XSHA1', 'XSHA256'
}

sip_methods =
{
    'INVITE', 'CANCEL', 'ACK', 'BYE', 'REGISTER', 'OPTIONS', 'REFER', 'SUBSCRIBE',
    'UPDATE', 'JOIN', 'INFO', 'MESSAGE', 'NOTIFY', 'PRACK'
}

isakmp_hex = { '?????????????????|01|', '?????????????????|10|' }

telnet_commands =
{
    '|FF F0|', '|FF F1|', '|FF F2|', '|FF F3|',
    '|FF F4|', '|FF F5|', '|FF F6|', '|FF F7|',
    '|FF F8|', '|FF F9|', '|FF FA|', '|FF FB|',
    '|FF FC|', '|FF FD|', '|FF FE|', '|FF FF|'
}

default_wizard =
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
-- default references
---------------------------------------------------------------------------

references =
{
    { name = 'bugtraq',   url = 'http://www.securityfocus.com/bid/' },
    { name = 'cve',       url = 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=' },
    { name = 'arachNIDS', url = 'http://www.whitehats.com/info/IDS' },
    { name = 'osvdb',     url = 'http://osvdb.org/show/osvdb/' },
    { name = 'McAfee', url = 'http://vil.nai.com/vil/content/v_' },
    { name = 'nessus', url = 'http://cgi.nessus.org/plugins/dump.php3?id=' },
    { name = 'url',    url = 'http://' },
    { name = 'msb',    url = 'http://technet.microsoft.com/en-us/security/bulletin/' }
}

---------------------------------------------------------------------------
-- default classifications
---------------------------------------------------------------------------

classifications =
{
    { name = 'not-suspicious', priority = 3,
      text = 'Not Suspicious Traffic' },

    { name = 'unknown', priority = 3,
      text = 'Unknown Traffic' },

    { name = 'bad-unknown', priority = 2,
      text = 'Potentially Bad Traffic' },

    { name = 'attempted-recon', priority = 2,
      text = 'Attempted Information Leak' },

    { name = 'successful-recon-limited', priority = 2,
      text = 'Information Leak' },

    { name = 'successful-recon-largescale', priority = 2,
      text = 'Large Scale Information Leak' },

    { name = 'attempted-dos', priority = 2,
      text = 'Attempted Denial of Service' },

    { name = 'successful-dos', priority = 2,
      text = 'Denial of Service' },

    { name = 'attempted-user', priority = 1,
      text = 'Attempted User Privilege Gain' },

    { name = 'unsuccessful-user', priority = 1,
      text = 'Unsuccessful User Privilege Gain' },

    { name = 'successful-user', priority = 1,
      text = 'Successful User Privilege Gain' },

    { name = 'attempted-admin', priority = 1,
      text = 'Attempted Administrator Privilege Gain' },

    { name = 'successful-admin', priority = 1,
      text = 'Successful Administrator Privilege Gain' },

    { name = 'rpc-portmap-decode', priority = 2,
      text = 'Decode of an RPC Query' },

    { name = 'shellcode-detect', priority = 1,
      text = 'Executable code was detected' },

    { name = 'string-detect', priority = 3,
      text = 'A suspicious string was detected' },

    { name = 'suspicious-filename-detect', priority = 2,
      text = 'A suspicious filename was detected' },

    { name = 'suspicious-login', priority = 2,
      text = 'An attempted login using a suspicious username was detected' },

    { name = 'system-call-detect', priority = 2,
      text = 'A system call was detected' },

    { name = 'tcp-connection', priority = 4,
      text = 'A TCP connection was detected' },

    { name = 'trojan-activity', priority = 1,
      text = 'A Network Trojan was detected' },

    { name = 'unusual-client-port-connection', priority = 2,
      text = 'A client was using an unusual port' },

    { name = 'network-scan', priority = 3,
      text = 'Detection of a Network Scan' },

    { name = 'denial-of-service', priority = 2,
      text = 'Detection of a Denial of Service Attack' },

    { name = 'non-standard-protocol', priority = 2,
      text = 'Detection of a non-standard protocol or event' },

    { name = 'protocol-command-decode', priority = 3,
      text = 'Generic Protocol Command Decode' },

    { name = 'web-application-activity', priority = 2,
      text = 'access to a potentially vulnerable web application' },

    { name = 'web-application-attack', priority = 1,
      text = 'Web Application Attack' },

    { name = 'misc-activity', priority = 3,
      text = 'Misc activity' },

    { name = 'misc-attack', priority = 2,
      text = 'Misc Attack' },

    { name = 'icmp-event', priority = 3,
      text = 'Generic ICMP event' },

    { name = 'inappropriate-content', priority = 1,
      text = 'Inappropriate Content was Detected' },

    { name = 'policy-violation', priority = 1,
      text = 'Potential Corporate Privacy Violation' },

    { name = 'default-login-attempt', priority = 2,
      text = 'Attempt to login by a default username and password' },

    { name = 'sdf', priority = 2,
      text = 'Senstive Data' },

    { name = 'file-format', priority = 1,
      text = 'Known malicious file or file based exploit' },

    { name = 'malware-cnc', priority = 1,
      text = 'Known malware command and control traffic' },

    { name = 'client-side-exploit', priority = 1,
      text = 'Known client side exploit attempt' }
}

