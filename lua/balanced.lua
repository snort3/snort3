---------------------------------------------------------------------------
-- balanced connectivity and security policy
-- use with -c snort.lua --tweaks balanced
---------------------------------------------------------------------------

arp_spoof = nil

http_inspect.request_depth = 300
http_inspect.response_depth = 500

port_scan = nil

stream_ip.min_frag_length = 16

