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
dofile(conf_dir .. '/classification.lua')
dofile(conf_dir .. '/reference.lua')

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

-- uncomment ppm if you built with --enable-ppm
--ppm = { }

-- uncomment profile if you built with --enable-perfprofile
--profile = { }

-- uncomment normalizer if you are inline or not --pedantic
--normalizer = { }

stream = { }
stream_ip = { }
stream_icmp = { }
stream_tcp = { }
stream_udp = { }

perf_monitor = { }

arp_spoof = { }
back_orifice = { }
rpc_decode = { }
port_scan = { }
telnet = { }

-- use http_inspect or new_http_inspect (incomplete)
http_inspect = { }
--new_http_inspect = { }

ftp_server = default_ftp_server
ftp_client = { }
ftp_data = { }

wizard = default_wizard

---------------------------------------------------------------------------
-- define / load rules and filters
---------------------------------------------------------------------------

local_rules =
[[
# snort-classic comments, includes, and rules with $VARIABLES
#
# this rule works the the extra luajit rule plugin 'find':
#alert tcp any any -> any [80 81] ( sid:1; msg:"test"; http_method; find:"pat = 'GET'"; )
]]

ips =
{
    include = conf_dir .. '/sample.rules',
    --rules = local_rules,
    --enable_builtin_rules = true
}

---------------------------------------------------------------------------
-- set up any custom loggers
---------------------------------------------------------------------------

--alert_test = { file = false }

