---------------------------------------------------------------------------
-- Snort++ configuration
---------------------------------------------------------------------------

---------------------------------------------------------------------------
-- setup environment
---------------------------------------------------------------------------
-- given:
-- export DIR=/install/path
-- configure --prefix=$DIR
-- make install
--
-- then:
-- export LUA_PATH=$DIR/include/snort/lua/?.lua\;\;
-- export SNORT_LUA_PATH=$DIR/conf/
---------------------------------------------------------------------------

---------------------------------------------------------------------------
-- setup the basics
---------------------------------------------------------------------------

require('snort_config')  -- for loading

-- Setup the network addresses you are protecting
HOME_NET = 'any'

-- Set up the external network addresses.
-- (leave as "any" in most situations)
EXTERNAL_NET = 'any'

conf_dir = os.getenv('SNORT_LUA_PATH')

if ( not conf_dir ) then
    conf_dir = '.'
end

dofile(conf_dir .. '/snort_defaults.lua')
dofile(conf_dir .. '/file_magic.lua')

---------------------------------------------------------------------------
-- configure modules
---------------------------------------------------------------------------
--
-- mod = { } uses internal defaults
-- you can see them with snort --help-module mod
-- comment or delete to disable mod functionality
--
-- you can also use default_ftp_server and default_wizard
---------------------------------------------------------------------------


-- uncomment normalizer if you are inline or not --pedantic
--normalizer = { }

--latency = { }
--profiler = { }
--perf_monitor = { }

stream = { }
stream_ip = { }
stream_icmp = { }
stream_tcp = { }
stream_udp = { }
stream_user = { }
stream_file = { }

arp_spoof = { }
back_orifice = { }
dnp3 = { }
dns = { }
gtp_inspect = default_gtp
imap = { }
smtp = { }
pop = { }
port_scan = { }
reputation = { }
rpc_decode = { }
sip = { }
ssh = { }
ssl = { }
telnet = { }

-- use http_inspect or new_http_inspect (incomplete)
http_inspect = { }
--new_http_inspect = { }

ftp_server = default_ftp_server
ftp_client = { }
ftp_data = { }

file_id =
{
    enable_type = true,
    enable_signature = true,
    file_rules = file_magic,
}

wizard = default_wizard

