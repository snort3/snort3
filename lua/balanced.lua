---------------------------------------------------------------------------
-- balanced connectivity and security policy
-- use with -c snort.lua --tweaks balanced
---------------------------------------------------------------------------

http_inspect.request_depth = 300
http_inspect.response_depth = 500

normalizer.tcp =
{
    ips = false,
    rsv = false,
    pad = false,
    req_urg = false,
    req_pay = false,
    req_urp = false,
    block = false,
}

port_scan = nil

