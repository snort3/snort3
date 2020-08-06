---------------------------------------------------------------------------
-- balanced connectivity and security policy
-- use with -c snort.lua --tweaks balanced
---------------------------------------------------------------------------

arp_spoof = nil

detection = { pcre_override = false }

http_inspect.request_depth = 300
http_inspect.response_depth = 500

port_scan = nil

stream_ip.min_frag_length = 16

table.insert(
    binder, 1, -- add http port binding to appease the perf gods
    { when = { proto = 'tcp', ports = '80', role='server' }, use = { type = 'http_inspect' } })

